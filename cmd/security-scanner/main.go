package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"security-scanner/internal/agent"
	"security-scanner/internal/app"
	"security-scanner/internal/bulk"
	"security-scanner/internal/history"
	"security-scanner/internal/llm"
	matchengine "security-scanner/internal/match"
	"security-scanner/internal/output"
	"security-scanner/internal/policy"
	"security-scanner/internal/preflight"
	"security-scanner/internal/redact"
	"security-scanner/internal/remediation"
	"security-scanner/internal/scan"
	"security-scanner/internal/targeting"
	"security-scanner/internal/triage"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	checkedStdout := &checkedWriter{writer: stdout}
	checkedStderr := &checkedWriter{writer: redact.Writer(stderr)}
	code := runCommand(args, checkedStdout, checkedStderr)
	if checkedStdout.Err() != nil || checkedStderr.Err() != nil {
		return 2
	}
	return code
}

func runCommand(args []string, stdout, stderr *checkedWriter) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "inventory":
		return runInventory(args[1:], stdout, stderr)
	case "providers":
		return runProviders(stdout)
	case "scans":
		return runScans(args[1:], stdout, stderr)
	case "findings":
		return runFindings(args[1:], stdout, stderr)
	case "bulk-scan":
		return runBulkScan(args[1:], stdout, stderr)
	case "validate", "patch":
		return runRemediation(args[0], args[1:], stdout, stderr)
	case "version", "--version", "-version":
		stdout.Println(version)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		stderr.Printf("unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runScan(args []string, stdout, stderr *checkedWriter) int {
	if len(args) > 0 && args[0] == "preflight" {
		return runPreflight(args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var excludes stringListFlag
	var paths pathListFlag
	target := flags.String("target", ".", "repository directory to scan")
	outDir := flags.String("out", "", "artifact directory (default: per-user scanner state directory)")
	flags.StringVar(outDir, "output-dir", "", "artifact directory (alias for --out)")
	diffRef := flags.String("diff", "", "scan files changed from the specified git revision")
	workingTree := flags.Bool("working-tree", false, "scan tracked and untracked working-tree changes")
	dryRun := flags.Bool("dry-run", false, "validate configuration and print the resolved scan without model calls")
	archiveExisting := flags.Bool("archive-existing", false, "archive a non-empty output directory before writing")
	failOnSeverity := flags.String("fail-on-severity", "", "return exit 1 when a finding meets this severity threshold")
	provider := flags.String("provider", "", "model provider; run 'providers' to list choices")
	model := flags.String("model", "", "provider model or deployment name")
	apiKey := flags.String("api-key", "", "provider API key (prefer the provider's environment variable)")
	baseURL := flags.String("base-url", "", "custom provider API base URL")
	apiVersion := flags.String("api-version", "", "provider API version; required by Azure OpenAI")
	authMode := flags.String("auth", "auto", "authentication mode: auto, env, api-key, or none")
	maxOutputTokens := flags.Int("max-output-tokens", 0, "provider output-token limit; 0 uses provider default")
	userContext := flags.String("context", "", "additional threat-model context, treated as untrusted data")
	scanPrompt := flags.String("scan-prompt", "", "custom coordinator prompt extension")
	scanPromptFile := flags.String("scan-prompt-file", "", "read custom coordinator prompt extension from file")
	followUpPrompt := flags.String("follow-up-prompt", "", "custom specialist follow-up prompt extension")
	followUpPromptFile := flags.String("follow-up-prompt-file", "", "read custom specialist follow-up prompt extension from file")
	maxFileBytes := flags.Int64("max-file-bytes", 1024*1024, "maximum reviewable file size")
	maxIterations := flags.Int("max-iterations", 80, "maximum reasoning iterations per agent")
	maxAgentConcurrency := flags.Int("max-agent-concurrency", 4, "maximum concurrent model requests across agents")
	maxDuration := flags.Duration("max-duration", 45*time.Minute, "overall scan timeout")
	requestTimeout := flags.Duration("request-timeout", 10*time.Minute, "timeout per model request")
	quiet := flags.Bool("quiet", false, "suppress progress messages")
	jsonProgress := flags.Bool("json-progress", false, "write JSON progress events to stderr")
	jsonProgressStrict := flags.Bool("json-progress-strict", false, "with --json-progress, emit only JSON progress events on stderr")
	verbose := flags.Bool("verbose", false, "print redacted scan diagnostics to stderr")
	flags.Var(&excludes, "exclude", "repository-relative directory to exclude; repeatable")
	flags.Var(&paths, "path", "repository-relative file or directory to scan; repeatable")
	flags.Usage = func() {
		stderr.Println("Usage: security-scanner scan [options]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		stderr.Println("scan does not accept positional arguments; use --target")
		return 2
	}
	resolvedScanPrompt, err := resolvePromptOverride(*scanPrompt, *scanPromptFile, "scan")
	if err != nil {
		stderr.Printf("scan failed: %v\n", err)
		return 2
	}
	resolvedFollowUpPrompt, err := resolvePromptOverride(*followUpPrompt, *followUpPromptFile, "follow-up")
	if err != nil {
		stderr.Printf("scan failed: %v\n", err)
		return 2
	}
	if *jsonProgressStrict && !*jsonProgress {
		stderr.Println("scan failed: --json-progress-strict requires --json-progress")
		return 2
	}
	emitLine := func(message string) {
		if !*jsonProgressStrict {
			stderr.Println(message)
		}
	}
	emitf := func(format string, args ...any) {
		if !*jsonProgressStrict {
			stderr.Printf(format, args...)
		}
	}
	diagnosticOutput := stderr
	if *jsonProgressStrict {
		diagnosticOutput = nil
	}
	diagnostic := newDiagnosticLogger(*verbose, diagnosticOutput)
	diagnostic.Log("scan.configuration", map[string]any{
		"version":               version,
		"dry_run":               *dryRun,
		"max_file_bytes":        *maxFileBytes,
		"max_iterations":        *maxIterations,
		"max_agent_concurrency": *maxAgentConcurrency,
		"max_duration":          maxDuration.String(),
		"request_timeout":       requestTimeout.String(),
	})
	estimator := newScanProgressEstimator()
	emitJSONProgress := func(message, phase string, percent int, status string) {
		if !*jsonProgress {
			return
		}
		data, err := json.Marshal(struct {
			Event     string `json:"event"`
			Timestamp string `json:"timestamp"`
			Message   string `json:"message"`
			Phase     string `json:"phase,omitempty"`
			Percent   int    `json:"percent,omitempty"`
			Status    string `json:"status,omitempty"`
		}{
			Event:     "scan.progress",
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Message:   message,
			Phase:     phase,
			Percent:   percent,
			Status:    status,
		})
		if err != nil {
			emitf("[scan] encode progress: %v\n", err)
			return
		}
		stderr.Println(string(data))
	}
	emitTerminalProgress := func(message, status string) {
		emitJSONProgress(message, "completed", 100, status)
	}
	if *maxAgentConcurrency <= 0 {
		diagnostic.Log("scan.failed", map[string]any{"classification": "configuration"})
		emitTerminalProgress("scan failed", "failed")
		emitLine("scan failed: --max-agent-concurrency must be positive")
		return 2
	}
	threshold, err := policy.ParseSeverity(*failOnSeverity)
	if err != nil {
		diagnostic.Log("scan.failed", map[string]any{"classification": "configuration"})
		emitTerminalProgress("scan failed", "failed")
		emitf("scan failed: %v\n", err)
		return 2
	}
	ctx, stop, interruptionCode := newSignalContext(context.Background())
	defer stop()
	if *maxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *maxDuration)
		defer cancel()
	}
	var progress func(string)
	if !*quiet || *jsonProgress || diagnostic.Enabled() {
		progress = func(message string) {
			diagnostic.Log("scan.progress", map[string]any{"message": message})
			if *jsonProgress {
				phase, percent := estimator.observe(message)
				emitJSONProgress(message, phase, percent, "in_progress")
			} else if !*quiet {
				stderr.Printf("[scan] %s\n", message)
			}
		}
	}
	resolution, err := targeting.Resolve(ctx, *target, targeting.Selector{Paths: paths, DiffRef: *diffRef, WorkingTree: *workingTree})
	if err != nil {
		diagnostic.Log("scan.failed", map[string]any{"classification": "target"})
		emitTerminalProgress("scan failed", "failed")
		emitf("scan failed: %v\n", err)
		return 2
	}
	diagnostic.Log("scan.target_resolved", map[string]any{
		"mode":       resolution.Mode,
		"path_count": len(resolution.Paths),
		"reference":  resolution.Ref,
	})
	options := app.Options{
		Target:              *target,
		OutputDir:           *outDir,
		Provider:            *provider,
		Model:               *model,
		APIKey:              *apiKey,
		BaseURL:             *baseURL,
		APIVersion:          *apiVersion,
		AuthMode:            *authMode,
		MaxOutputTokens:     *maxOutputTokens,
		UserContext:         *userContext,
		Excludes:            excludes,
		Includes:            resolution.Paths,
		TargetMode:          resolution.Mode,
		TargetRef:           resolution.Ref,
		ArchiveExisting:     *archiveExisting,
		MaxFileBytes:        *maxFileBytes,
		MaxIterations:       *maxIterations,
		MaxAgentConcurrency: *maxAgentConcurrency,
		RequestTimeout:      *requestTimeout,
		MaxDuration:         *maxDuration,
		FailOnSeverity:      *failOnSeverity,
		ScanPrompt:          resolvedScanPrompt,
		FollowUpPrompt:      resolvedFollowUpPrompt,
		Progress:            progress,
	}
	if *dryRun {
		prepared, err := app.Prepare(options, time.Now().UTC())
		if err != nil {
			diagnostic.Log("scan.failed", map[string]any{"classification": "preflight"})
			emitTerminalProgress("scan failed", "failed")
			emitf("scan failed: %v\n", err)
			return 2
		}
		payload := struct {
			DryRun      bool                 `json:"dry_run"`
			Target      targeting.Resolution `json:"target_selection"`
			Preparation *app.Preparation     `json:"scan"`
			Policy      policy.Evaluation    `json:"policy"`
		}{DryRun: true, Target: resolution, Preparation: prepared, Policy: policy.Evaluation{Threshold: threshold}}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			diagnostic.Log("scan.failed", map[string]any{"classification": "output"})
			emitTerminalProgress("scan failed", "failed")
			emitf("write dry-run result: %v\n", err)
			return 2
		}
		diagnostic.Log("scan.preflight.completed", map[string]any{
			"provider": prepared.Provider,
			"model":    prepared.ModelName,
			"files":    len(prepared.Inventory.Files),
		})
		emitTerminalProgress("scan dry-run completed", "completed")
		return 0
	}
	result, err := app.Run(ctx, options)
	if err != nil {
		classification := "runtime"
		if errors.Is(err, context.Canceled) {
			classification = "interrupted"
		} else if errors.Is(err, context.DeadlineExceeded) {
			classification = "deadline"
		}
		diagnostic.Log("scan.failed", map[string]any{"classification": classification})
		if errors.Is(err, context.Canceled) {
			emitTerminalProgress("scan interrupted", "interrupted")
			emitf("scan interrupted: %v\n", err)
			return interruptionCode()
		} else if errors.Is(err, context.DeadlineExceeded) {
			emitTerminalProgress("scan failed", "failed")
			emitf("scan failed: %v\n", err)
		} else {
			emitTerminalProgress("scan failed", "failed")
			emitf("scan failed: %v\n", err)
		}
		return 2
	}
	reportPath := filepath.Join(result.OutDir, "report.md")
	stdout.Printf("Report: %s\n", reportPath)
	stdout.Printf("Status: %s\n", result.Manifest.Status)
	stdout.Printf("Model: %s/%s\n", result.Manifest.Provider, result.Manifest.Model)
	stdout.Printf("Findings: %d\n", result.Manifest.FindingCount)
	stdout.Printf("Coverage: %d/%d reviewed (%d skipped, %d unreviewed)\n",
		result.Coverage.Summary.Reviewed, result.Coverage.Summary.Total,
		result.Coverage.Summary.Skipped, result.Coverage.Summary.Unreviewed)
	evaluation := policy.Evaluate(result.Findings.Findings, threshold)
	exitCode := 0
	if result.Coverage.Summary.Unreviewed > 0 {
		exitCode = 2
	} else if evaluation.Violated {
		exitCode = 1
	}
	diagnostic.Log("scan.completed", map[string]any{
		"scan_id":    result.Manifest.ScanID,
		"status":     result.Manifest.Status,
		"findings":   result.Manifest.FindingCount,
		"unreviewed": result.Coverage.Summary.Unreviewed,
		"exit_code":  exitCode,
	})
	if result.Coverage.Summary.Unreviewed > 0 {
		emitTerminalProgress("scan completed with incomplete coverage", "failed")
		emitLine("scan completed with incomplete coverage")
		return 2
	}
	if evaluation.Violated {
		emitTerminalProgress("scan policy violated", "failed")
		emitf("scan policy violated: %d finding(s) at or above %s\n", len(evaluation.Matches), threshold)
		return 1
	}
	emitTerminalProgress("scan completed", "completed")
	return 0
}

func runPreflight(args []string, stdout, stderr *checkedWriter) int {
	flags := flag.NewFlagSet("scan preflight", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var excludes stringListFlag
	var paths pathListFlag
	target := flags.String("target", ".", "repository directory to validate")
	outDir := flags.String("output-dir", "", "artifact directory")
	provider := flags.String("provider", "", "model provider")
	modelName := flags.String("model", "", "provider model or deployment name")
	apiKey := flags.String("api-key", "", "provider API key")
	baseURL := flags.String("base-url", "", "custom provider API base URL")
	apiVersion := flags.String("api-version", "", "provider API version")
	authMode := flags.String("auth", "auto", "authentication mode: auto, env, api-key, or none")
	diffRef := flags.String("diff", "", "validate files changed from a git revision")
	workingTree := flags.Bool("working-tree", false, "validate working-tree target resolution")
	archiveExisting := flags.Bool("archive-existing", false, "allow archival of existing output during the real scan")
	maxFileBytes := flags.Int64("max-file-bytes", 1024*1024, "maximum reviewable file size")
	asJSON := flags.Bool("json", false, "write machine-readable JSON")
	scanPrompt := flags.String("scan-prompt", "", "custom coordinator prompt extension")
	scanPromptFile := flags.String("scan-prompt-file", "", "read custom coordinator prompt extension from file")
	followUpPrompt := flags.String("follow-up-prompt", "", "custom specialist follow-up prompt extension")
	followUpPromptFile := flags.String("follow-up-prompt-file", "", "read custom specialist follow-up prompt extension from file")
	flags.Var(&excludes, "exclude", "repository-relative exclusion; repeatable")
	flags.Var(&paths, "path", "repository-relative file or directory; repeatable")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	resolvedScanPrompt, err := resolvePromptOverride(*scanPrompt, *scanPromptFile, "scan")
	if err != nil {
		stderr.Printf("scan failed: %v\n", err)
		return 2
	}
	resolvedFollowUpPrompt, err := resolvePromptOverride(*followUpPrompt, *followUpPromptFile, "follow-up")
	if err != nil {
		stderr.Printf("scan failed: %v\n", err)
		return 2
	}
	ctx := context.Background()
	resolution, err := targeting.Resolve(ctx, *target, targeting.Selector{Paths: paths, DiffRef: *diffRef, WorkingTree: *workingTree})
	if err != nil {
		result := preflight.Result{Checks: []preflight.Check{{Name: "target", Status: "error", Message: redact.Text(err.Error())}}}
		if *asJSON {
			_ = writeJSON(result, stdout, stderr)
		} else {
			stderr.Printf("[error] target: %v\n", err)
		}
		return 2
	}
	result := preflight.Run(ctx, app.Options{
		Target: *target, OutputDir: *outDir, Provider: *provider, Model: *modelName, APIKey: *apiKey,
		BaseURL: *baseURL, APIVersion: *apiVersion, AuthMode: *authMode, Excludes: excludes,
		Includes: resolution.Paths, TargetMode: resolution.Mode, TargetRef: resolution.Ref,
		ArchiveExisting: *archiveExisting, MaxFileBytes: *maxFileBytes,
		ScanPrompt: resolvedScanPrompt, FollowUpPrompt: resolvedFollowUpPrompt,
	})
	if *asJSON {
		_ = writeJSON(result, stdout, stderr)
	} else {
		for _, check := range result.Checks {
			stdout.Printf("[%s] %s: %s\n", check.Status, check.Name, check.Message)
		}
		if result.OK {
			stdout.Printf("Resolved: %s/%s, %d files\n", result.Provider, result.Model, result.FilesTotal)
		}
	}
	if !result.OK {
		return 2
	}
	return 0
}

func runProviders(stdout *checkedWriter) int {
	stdout.Println("PROVIDER          API KEY ENV             MODEL ENV             BASE URL ENV")
	for _, provider := range llm.DefaultRegistry().Providers() {
		apiKeyEnv := provider.APIKeyEnv
		if !provider.RequiresAPIKey {
			apiKeyEnv = "(optional)"
		}
		stdout.Printf("%-17s %-23s %-21s %s\n", provider.Name, apiKeyEnv, provider.ModelEnv, provider.BaseURLEnv)
	}
	return 0
}

func runScans(args []string, stdout, stderr *checkedWriter) int {
	if len(args) == 0 {
		stderr.Println("Usage: security-scanner scans <list|show|rerun|match|compare> [options]")
		return 2
	}
	store, err := history.DefaultStore()
	if err != nil {
		stderr.Printf("scans failed: %v\n", err)
		return 2
	}
	switch args[0] {
	case "list":
		flags := flag.NewFlagSet("scans list", flag.ContinueOnError)
		flags.SetOutput(stderr)
		target := flags.String("target", "", "only scans for this repository root")
		scanRoot := flags.String("scan-root", "", "only scans stored below this output root")
		asJSON := flags.Bool("json", false, "write machine-readable JSON")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return 2
		}
		records, err := store.List(*target)
		if err != nil {
			stderr.Printf("scans list failed: %v\n", err)
			return 2
		}
		if strings.TrimSpace(*scanRoot) != "" {
			absoluteRoot, resolveErr := filepath.Abs(*scanRoot)
			if resolveErr != nil {
				stderr.Printf("scans list failed: %v\n", resolveErr)
				return 2
			}
			filtered := records[:0]
			for _, record := range records {
				rel, relErr := filepath.Rel(absoluteRoot, record.OutputDir)
				if relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					filtered = append(filtered, record)
				}
			}
			records = filtered
		}
		if *asJSON {
			return writeJSON(records, stdout, stderr)
		}
		stdout.Println("SCAN ID                         STATUS                FINDINGS  COMPLETED                 TARGET")
		for _, record := range records {
			stdout.Printf("%-31s %-21s %-9d %-25s %s\n", record.ScanID, record.Status, record.FindingCount, record.CompletedAt.Format(time.RFC3339), record.Target)
		}
		return 0
	case "show":
		if len(args) != 2 {
			stderr.Println("Usage: security-scanner scans show SCAN_ID")
			return 2
		}
		result, err := loadHistoryResult(store, args[1])
		if err != nil {
			stderr.Printf("scans show failed: %v\n", err)
			return 2
		}
		return writeJSON(result, stdout, stderr)
	case "rerun":
		scanID, verbose, err := parseRerunArgs(args[1:])
		if err != nil {
			stderr.Printf("scans rerun failed: %v\n", err)
			stderr.Println("Usage: security-scanner scans rerun SCAN_ID [--verbose]")
			return 2
		}
		record, err := store.Get(scanID)
		if err != nil {
			stderr.Printf("scans rerun failed: %v\n", err)
			return 2
		}
		scanArgs, err := rerunScanArgs(record, verbose)
		if err != nil {
			stderr.Printf("scans rerun failed: %v\n", err)
			return 2
		}
		return runScan(scanArgs, stdout, stderr)
	case "match", "compare":
		flags := flag.NewFlagSet("scans "+args[0], flag.ContinueOnError)
		flags.SetOutput(stderr)
		asJSON := flags.Bool("json", args[0] == "match", "write machine-readable JSON")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 2 {
			stderr.Printf("Usage: security-scanner scans %s BEFORE AFTER [--json]\n", args[0])
			return 2
		}
		before, err := loadHistoryResult(store, flags.Arg(0))
		if err != nil {
			stderr.Printf("scans %s failed: %v\n", args[0], err)
			return 2
		}
		after, err := loadHistoryResult(store, flags.Arg(1))
		if err != nil {
			stderr.Printf("scans %s failed: %v\n", args[0], err)
			return 2
		}
		comparison := matchengine.Compare(before.Findings, after.Findings)
		beforeRecord, recordErr := store.Get(flags.Arg(0))
		if recordErr == nil {
			records, _ := store.List(beforeRecord.Target)
			older := make([]scan.FindingsDocument, 0)
			for _, record := range records {
				if !record.StartedAt.Before(beforeRecord.StartedAt) {
					continue
				}
				if historical, loadErr := history.LoadResult(record); loadErr == nil {
					older = append(older, historical.Findings)
				}
			}
			comparison = matchengine.MarkReopened(comparison, older)
		}
		if *asJSON {
			return writeJSON(comparison, stdout, stderr)
		}
		stdout.Printf("Comparison: %s -> %s\n", comparison.BeforeScanID, comparison.AfterScanID)
		stdout.Printf("Persisting: %d\nNew: %d\nReopened: %d\nResolved: %d\nUnknown: %d\n", len(comparison.Persisting), len(comparison.New), len(comparison.Reopened), len(comparison.Resolved), len(comparison.Unknown))
		for _, finding := range comparison.New {
			stdout.Printf("+ [%s] %s: %s\n", finding.Severity, finding.ID, finding.Title)
		}
		for _, finding := range comparison.Reopened {
			stdout.Printf("! [%s] %s: %s\n", finding.Severity, finding.ID, finding.Title)
		}
		for _, finding := range comparison.Resolved {
			stdout.Printf("- [%s] %s: %s\n", finding.Severity, finding.ID, finding.Title)
		}
		return 0
	default:
		stderr.Printf("unknown scans command %q\n", args[0])
		return 2
	}
}

func runFindings(args []string, stdout, stderr *checkedWriter) int {
	if len(args) < 2 || args[0] != "false-positive" {
		stderr.Println("Usage: security-scanner findings false-positive OCCURRENCE_ID --reason TEXT [--scan SCAN_ID]")
		return 2
	}
	occurrenceID := args[1]
	flags := flag.NewFlagSet("findings false-positive", flag.ContinueOnError)
	flags.SetOutput(stderr)
	reason := flags.String("reason", "", "analyst rationale for the decision")
	scanID := flags.String("scan", "", "scan containing the occurrence; defaults to newest match")
	if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	if strings.TrimSpace(*reason) == "" {
		stderr.Println("findings false-positive requires --reason")
		return 2
	}
	lookupID := occurrenceID
	if strings.Contains(occurrenceID, ":") {
		occurrenceScanID, findingID, err := triage.ParseOccurrenceID(occurrenceID)
		if err != nil {
			stderr.Printf("findings failed: %v\n", err)
			return 2
		}
		if *scanID != "" && *scanID != occurrenceScanID {
			stderr.Println("findings failed: occurrence scan and --scan disagree")
			return 2
		}
		*scanID, lookupID = occurrenceScanID, findingID
	}
	historyStore, err := history.DefaultStore()
	if err != nil {
		stderr.Printf("findings failed: %v\n", err)
		return 2
	}
	records, err := historyStore.List("")
	if err != nil {
		stderr.Printf("findings failed: %v\n", err)
		return 2
	}
	var selected history.Record
	var selectedFinding *scan.Finding
	for _, record := range records {
		if *scanID != "" && record.ScanID != *scanID {
			continue
		}
		result, loadErr := history.LoadResult(record)
		if loadErr != nil {
			continue
		}
		for i := range result.Findings.Findings {
			if result.Findings.Findings[i].ID == lookupID {
				selected, selectedFinding = record, &result.Findings.Findings[i]
				break
			}
		}
		if selectedFinding != nil {
			break
		}
	}
	if selectedFinding == nil {
		stderr.Printf("finding occurrence %q was not found\n", occurrenceID)
		return 2
	}
	store, err := triage.DefaultStore()
	if err != nil {
		stderr.Printf("findings failed: %v\n", err)
		return 2
	}
	fullOccurrenceID := occurrenceID
	if !strings.Contains(occurrenceID, ":") {
		fullOccurrenceID = selected.ScanID + ":" + occurrenceID
	}
	decision := triage.Decision{OccurrenceID: fullOccurrenceID, Fingerprint: selectedFinding.Fingerprint, ScanID: selected.ScanID, Target: selected.Target, Reason: *reason, UpdatedAt: time.Now().UTC()}
	if err := store.SetDecision(decision); err != nil {
		stderr.Printf("findings failed: %v\n", err)
		return 2
	}
	decision.Disposition = "false_positive"
	return writeJSON(decision, stdout, stderr)
}

func runRemediation(kind string, args []string, stdout, stderr *checkedWriter) int {
	flags := flag.NewFlagSet(kind, flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "repository containing the code to review; inferred for artifacts")
	scanID := flags.String("scan", "", "scan containing a finding ID")
	provider := flags.String("provider", "", "model provider")
	modelName := flags.String("model", "", "provider model or deployment name")
	apiKey := flags.String("api-key", "", "provider API key")
	baseURL := flags.String("base-url", "", "custom provider API base URL")
	apiVersion := flags.String("api-version", "", "provider API version")
	authMode := flags.String("auth", "auto", "authentication mode: auto, env, api-key, or none")
	maxOutputTokens := flags.Int("max-output-tokens", 0, "provider output-token limit")
	maxFileBytes := flags.Int64("max-file-bytes", 1024*1024, "maximum reviewable file size")
	maxIterations := flags.Int("max-iterations", 40, "maximum reasoning iterations")
	maxAgentConcurrency := flags.Int("max-agent-concurrency", 4, "maximum concurrent model requests")
	requestTimeout := flags.Duration("request-timeout", 10*time.Minute, "timeout per model request")
	maxDuration := flags.Duration("max-duration", 30*time.Minute, "overall workflow timeout")
	exportPath := flags.String("export", "", "write the JSON result to a new file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		stderr.Printf("Usage: security-scanner %s [options] FINDING_OR_PROMPT\n", kind)
		return 2
	}
	if *maxAgentConcurrency <= 0 {
		stderr.Printf("%s failed: --max-agent-concurrency must be positive\n", kind)
		return 2
	}
	input := strings.TrimSpace(flags.Arg(0))
	if input == "" {
		stderr.Println("finding or prompt is required")
		return 2
	}
	if *scanID != "" || strings.HasPrefix(strings.ToUpper(input), "F-") {
		if resolvedInput, resolvedTarget, err := resolveReviewInput(input, *scanID); err != nil {
			stderr.Printf("%s failed: %v\n", kind, err)
			return 2
		} else {
			input, *target = resolvedInput, resolvedTarget
		}
	} else {
		resolved, err := remediation.ResolveInput(input, *target)
		if err != nil {
			stderr.Printf("%s failed: %v\n", kind, err)
			return 2
		}
		input, *target = resolved.Text, resolved.Target
	}
	ctx, stop, interruptionCode := newSignalContext(context.Background())
	defer stop()
	if *maxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *maxDuration)
		defer cancel()
	}
	prepared, err := app.Prepare(app.Options{
		Target: *target, Provider: *provider, Model: *modelName, APIKey: *apiKey, BaseURL: *baseURL,
		APIVersion: *apiVersion, AuthMode: *authMode, MaxOutputTokens: *maxOutputTokens, MaxFileBytes: *maxFileBytes,
		RequestTimeout: *requestTimeout,
	}, time.Now().UTC())
	if err != nil {
		stderr.Printf("%s failed: %v\n", kind, err)
		return 2
	}
	chatModel, _, err := llm.DefaultRegistry().Build(ctx, prepared.Model)
	if err != nil {
		stderr.Printf("%s failed: %v\n", kind, err)
		return 2
	}
	chatModel, err = llm.LimitConcurrency(chatModel, *maxAgentConcurrency)
	if err != nil {
		stderr.Printf("%s failed: %v\n", kind, err)
		return 2
	}
	reviewer := agent.NewEinoReviewer(chatModel, agent.Config{MaxIterations: *maxIterations}, prepared.Inventory)
	var result any
	if kind == "validate" {
		result, err = reviewer.Validate(ctx, input)
	} else {
		result, err = reviewer.ProposePatch(ctx, input)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			stderr.Printf("%s interrupted: %v\n", kind, err)
			return interruptionCode()
		}
		stderr.Printf("%s failed: %v\n", kind, err)
		return 2
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		stderr.Printf("%s failed: encode result: %v\n", kind, err)
		return 2
	}
	data = append(data, '\n')
	if *exportPath != "" {
		if err := writeNewFile(*exportPath, data); err != nil {
			stderr.Printf("%s export failed: %v\n", kind, err)
			return 2
		}
	}
	if _, err := stdout.Write(data); err != nil {
		stderr.Printf("write result: %v\n", err)
		return 2
	}
	return 0
}

func runBulkScan(args []string, stdout, stderr *checkedWriter) int {
	if len(args) == 0 {
		stderr.Println("Usage: security-scanner bulk-scan INPUT --output-dir PATH [options]")
		return 2
	}
	inputPath := args[0]
	flags := flag.NewFlagSet("bulk-scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputDir := flags.String("output-dir", "", "directory for isolated scans and the resumable receipt")
	workers := flags.Int("workers", 2, "maximum concurrent repository scans")
	retries := flags.Int("retries", 2, "retry count for failed scans")
	retryDelay := flags.Duration("retry-delay", time.Second, "initial exponential retry delay")
	maxScans := flags.Int("max-scans", 0, "cost guardrail limiting repositories; 0 is unlimited")
	maxBudget := flags.Float64("max-budget", 0, "maximum estimated cost units; 0 is unlimited")
	estimatedCost := flags.Float64("estimated-scan-cost", 0, "reserved cost units per repository")
	failOnSeverity := flags.String("fail-on-severity", "", "fail a repository when findings meet this threshold")
	provider := flags.String("provider", "", "model provider")
	modelName := flags.String("model", "", "provider model or deployment name")
	apiKey := flags.String("api-key", "", "provider API key")
	baseURL := flags.String("base-url", "", "custom provider API base URL")
	apiVersion := flags.String("api-version", "", "provider API version")
	authMode := flags.String("auth", "auto", "authentication mode: auto, env, api-key, or none")
	maxOutputTokens := flags.Int("max-output-tokens", 0, "provider output-token limit")
	maxFileBytes := flags.Int64("max-file-bytes", 1024*1024, "maximum reviewable file size")
	maxIterations := flags.Int("max-iterations", 80, "maximum reasoning iterations per agent")
	maxAgentConcurrency := flags.Int("max-agent-concurrency", 4, "maximum concurrent model requests per repository")
	requestTimeout := flags.Duration("request-timeout", 10*time.Minute, "timeout per model request")
	maxDuration := flags.Duration("max-duration", 45*time.Minute, "deadline for each repository scan")
	jsonProgress := flags.Bool("json-progress", false, "write JSON progress events")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *outputDir == "" || *workers <= 0 || *retries < 0 || *maxScans < 0 || *retryDelay <= 0 || *maxAgentConcurrency <= 0 {
		stderr.Println("bulk-scan requires --output-dir, positive --workers, and non-negative retry/guardrail values")
		return 2
	}
	threshold, err := policy.ParseSeverity(*failOnSeverity)
	if err != nil {
		stderr.Printf("bulk-scan failed: %v\n", err)
		return 2
	}
	inputJobs, err := bulk.ParseInput(inputPath)
	if err != nil {
		stderr.Printf("bulk-scan failed: %v\n", err)
		return 2
	}
	if *maxScans > 0 && len(inputJobs) > *maxScans {
		inputJobs = inputJobs[:*maxScans]
	}
	absOutput, err := filepath.Abs(*outputDir)
	if err != nil {
		stderr.Printf("bulk-scan failed: %v\n", err)
		return 2
	}
	jobs, err := bulk.PrepareJobs(inputJobs, absOutput)
	if err != nil {
		stderr.Printf("bulk-scan failed: %v\n", err)
		return 2
	}
	ctx, stop, interruptionCode := newSignalContext(context.Background())
	defer stop()
	progress := func(event bulk.Event) {
		if *jsonProgress {
			data, err := json.Marshal(event)
			if err != nil {
				stderr.Printf("[bulk] encode progress: %v\n", err)
				return
			}
			stderr.Println(string(data))
		} else {
			stderr.Printf("[bulk] %s %s attempt=%d %s\n", event.JobID, event.Status, event.Attempt, event.Message)
		}
	}
	receiptPath := filepath.Join(absOutput, "bulk-receipt.json")
	receipt, runErr := bulk.Run(ctx, jobs, func(parent context.Context, job bulk.Job) (string, error) {
		scanCtx := parent
		if *maxDuration > 0 {
			var cancel context.CancelFunc
			scanCtx, cancel = context.WithTimeout(parent, *maxDuration)
			defer cancel()
		}
		result, err := app.Run(scanCtx, app.Options{
			Target: job.Target, OutputDir: job.OutputDir, Provider: *provider, Model: *modelName,
			APIKey: *apiKey, BaseURL: *baseURL, APIVersion: *apiVersion, AuthMode: *authMode,
			MaxOutputTokens: *maxOutputTokens, MaxFileBytes: *maxFileBytes,
			MaxIterations: *maxIterations, RequestTimeout: *requestTimeout, ArchiveExisting: true,
			MaxAgentConcurrency: *maxAgentConcurrency, UserContext: job.Context,
		})
		if err != nil {
			return "", err
		}
		if result.Coverage.Summary.Unreviewed > 0 {
			return result.Manifest.ScanID, fmt.Errorf("incomplete coverage: %d unreviewed files", result.Coverage.Summary.Unreviewed)
		}
		if evaluation := policy.Evaluate(result.Findings.Findings, threshold); evaluation.Violated {
			return result.Manifest.ScanID, fmt.Errorf("severity policy violated by %d findings", len(evaluation.Matches))
		}
		return result.Manifest.ScanID, nil
	}, bulk.Config{
		Workers: *workers, MaxRetries: *retries, RetryDelay: *retryDelay, ReceiptPath: receiptPath,
		MaxBudget: *maxBudget, EstimatedCost: *estimatedCost, Resume: true, OnEvent: progress,
	})
	completed, failed := 0, 0
	for _, entry := range receipt.Jobs {
		if entry.Status == "completed" {
			completed++
		} else {
			failed++
		}
	}
	stdout.Printf("Receipt: %s\nCompleted: %d\nFailed: %d\n", receiptPath, completed, failed)
	if errors.Is(runErr, context.Canceled) {
		return interruptionCode()
	}
	if runErr != nil {
		stderr.Printf("bulk-scan failed: %v\n", runErr)
		return 2
	}
	if failed > 0 {
		return 2
	}
	return 0
}

func newSignalContext(parent context.Context) (context.Context, func(), func() int) {
	ctx, cancel := context.WithCancel(parent)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	var exitCodeMu sync.Mutex
	exitCode := 130
	go func() {
		select {
		case received := <-signals:
			exitCodeMu.Lock()
			exitCode = exitCodeForSignal(received)
			exitCodeMu.Unlock()
			cancel()
		case <-ctx.Done():
		}
	}()
	stop := func() {
		signal.Stop(signals)
		cancel()
	}
	return ctx, stop, func() int {
		exitCodeMu.Lock()
		defer exitCodeMu.Unlock()
		return exitCode
	}
}

func exitCodeForSignal(received os.Signal) int {
	if received == syscall.SIGTERM {
		return 143
	}
	return 130
}

func resolveReviewInput(input, scanID string) (string, string, error) {
	if scanID == "" && !strings.HasPrefix(strings.ToUpper(input), "F-") {
		return "", "", nil
	}
	store, err := history.DefaultStore()
	if err != nil {
		return "", "", err
	}
	records, err := store.List("")
	if err != nil {
		return "", "", err
	}
	for _, record := range records {
		if scanID != "" && record.ScanID != scanID {
			continue
		}
		result, err := history.LoadResult(record)
		if err != nil {
			continue
		}
		for _, finding := range result.Findings.Findings {
			if finding.ID == input {
				data, err := json.Marshal(finding)
				return string(data), record.Target, err
			}
		}
	}
	return "", "", fmt.Errorf("finding %q was not found", input)
}

func writeNewFile(path string, data []byte) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(absPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create export without overwriting: %w", err)
	}
	if err := output.SecurePrivateFile(absPath); err != nil {
		_ = file.Close()
		_ = os.Remove(absPath)
		return fmt.Errorf("secure export: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func loadHistoryResult(store *history.Store, scanID string) (*scan.Result, error) {
	record, err := store.Get(scanID)
	if err != nil {
		return nil, err
	}
	return history.LoadResult(record)
}

func parseRerunArgs(args []string) (string, bool, error) {
	var scanID string
	verbose := false
	for _, arg := range args {
		switch {
		case arg == "--verbose":
			verbose = true
		case strings.HasPrefix(arg, "--verbose="):
			value, err := strconv.ParseBool(strings.TrimPrefix(arg, "--verbose="))
			if err != nil {
				return "", false, fmt.Errorf("--verbose expects true or false")
			}
			verbose = value
		case strings.HasPrefix(arg, "-"):
			return "", false, fmt.Errorf("unknown option %q", arg)
		case scanID != "":
			return "", false, fmt.Errorf("expected exactly one scan ID")
		default:
			scanID = strings.TrimSpace(arg)
		}
	}
	if scanID == "" {
		return "", false, fmt.Errorf("scan ID is required")
	}
	return scanID, verbose, nil
}

func resolvePromptOverride(inlineValue, filePath, promptKind string) (string, error) {
	inline := strings.TrimSpace(inlineValue)
	path := strings.TrimSpace(filePath)
	if inline != "" && path != "" {
		return "", fmt.Errorf("use either --%s-prompt or --%s-prompt-file", promptKind, promptKind)
	}
	if path == "" {
		if err := validatePromptOverride(inline, promptKind); err != nil {
			return "", err
		}
		return inline, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read --%s-prompt-file: %w", promptKind, err)
	}
	resolved := strings.TrimSpace(string(content))
	if resolved == "" {
		return "", fmt.Errorf("--%s-prompt-file is empty", promptKind)
	}
	if err := validatePromptOverride(resolved, promptKind); err != nil {
		return "", err
	}
	return resolved, nil
}

func validatePromptOverride(value, promptKind string) error {
	if value == "" {
		return nil
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("--%s-prompt must be valid UTF-8 text", promptKind)
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("--%s-prompt cannot contain NUL characters", promptKind)
	}
	return nil
}

func rerunScanArgs(record history.Record, verbose bool) ([]string, error) {
	if strings.TrimSpace(record.Target) == "" || strings.TrimSpace(record.Provider) == "" || strings.TrimSpace(record.Model) == "" {
		return nil, fmt.Errorf("saved scan is missing its target, provider, or model")
	}
	args := []string{"--target", record.Target, "--provider", record.Provider, "--model", record.Model}
	if config := record.LaunchConfig; config != nil {
		if config.RequiresExplicitAPIKey {
			return nil, fmt.Errorf("saved scan used an explicit API key; API keys are not stored, so rerun the original command with --api-key")
		}
		authMode := strings.TrimSpace(config.AuthMode)
		switch authMode {
		case "", "auto", "env", "none":
			if authMode != "" {
				args = append(args, "--auth", authMode)
			}
		case "api-key":
			return nil, fmt.Errorf("saved scan used --auth api-key; API keys are not stored, so rerun the original command with --api-key")
		default:
			return nil, fmt.Errorf("saved scan has invalid authentication mode %q", authMode)
		}
		if config.BaseURL != "" {
			args = append(args, "--base-url", config.BaseURL)
		}
		if config.APIVersion != "" {
			args = append(args, "--api-version", config.APIVersion)
		}
		if config.MaxOutputTokens < 0 || config.MaxFileBytes < 0 || config.MaxIterations < 0 || config.MaxAgentConcurrency < 0 {
			return nil, fmt.Errorf("saved scan contains invalid negative runtime settings")
		}
		if config.MaxOutputTokens > 0 {
			args = append(args, "--max-output-tokens", strconv.Itoa(config.MaxOutputTokens))
		}
		if config.MaxFileBytes > 0 {
			args = append(args, "--max-file-bytes", strconv.FormatInt(config.MaxFileBytes, 10))
		}
		if config.MaxIterations > 0 {
			args = append(args, "--max-iterations", strconv.Itoa(config.MaxIterations))
		}
		if config.MaxAgentConcurrency > 0 {
			args = append(args, "--max-agent-concurrency", strconv.Itoa(config.MaxAgentConcurrency))
		}
		for _, setting := range []struct {
			flag  string
			value string
		}{
			{flag: "--request-timeout", value: config.RequestTimeout},
			{flag: "--max-duration", value: config.MaxDuration},
		} {
			if setting.value == "" {
				continue
			}
			duration, err := time.ParseDuration(setting.value)
			if err != nil || duration <= 0 {
				return nil, fmt.Errorf("saved scan has invalid %s value", setting.flag)
			}
			args = append(args, setting.flag, setting.value)
		}
		if config.UserContext != "" {
			args = append(args, "--context", config.UserContext)
		}
		if config.ScanPrompt != "" {
			args = append(args, "--scan-prompt", config.ScanPrompt)
		}
		if config.FollowUpPrompt != "" {
			args = append(args, "--follow-up-prompt", config.FollowUpPrompt)
		}
		for _, exclude := range config.Excludes {
			if strings.TrimSpace(exclude) == "" {
				return nil, fmt.Errorf("saved scan contains an empty exclusion")
			}
			args = append(args, "--exclude", exclude)
		}
		if severity := strings.TrimSpace(config.FailOnSeverity); severity != "" {
			if _, err := policy.ParseSeverity(severity); err != nil {
				return nil, fmt.Errorf("saved scan has invalid severity policy: %w", err)
			}
			args = append(args, "--fail-on-severity", severity)
		}
	}
	switch record.TargetMode {
	case "", "all":
	case "path":
		if len(record.TargetPaths) == 0 {
			return nil, fmt.Errorf("saved path scan contains no target paths")
		}
		for _, path := range record.TargetPaths {
			if strings.TrimSpace(path) == "" {
				return nil, fmt.Errorf("saved path scan contains an empty target path")
			}
			args = append(args, "--path", path)
		}
	case "diff":
		if strings.TrimSpace(record.TargetRef) == "" {
			return nil, fmt.Errorf("saved diff scan contains no Git reference")
		}
		args = append(args, "--diff", record.TargetRef)
	case "working_tree":
		args = append(args, "--working-tree")
	default:
		return nil, fmt.Errorf("saved scan has invalid target mode %q", record.TargetMode)
	}
	if verbose {
		args = append(args, "--verbose")
	}
	return args, nil
}

type diagnosticLogger struct {
	enabled bool
	output  *checkedWriter
}

func newDiagnosticLogger(requested bool, output *checkedWriter) diagnosticLogger {
	level := strings.TrimSpace(os.Getenv("SECURITY_SCANNER_LOG_LEVEL"))
	if level == "" {
		level = strings.TrimSpace(os.Getenv("LOG_LEVEL"))
	}
	return diagnosticLogger{enabled: requested || strings.EqualFold(level, "debug"), output: output}
}

func (logger diagnosticLogger) Enabled() bool { return logger.enabled }

func (logger diagnosticLogger) Log(event string, fields map[string]any) {
	if !logger.enabled || logger.output == nil {
		return
	}
	if len(fields) == 0 {
		logger.output.Printf("security-scanner: debug: %s\n", event)
		return
	}
	data, err := json.Marshal(fields)
	if err != nil {
		logger.output.Printf("security-scanner: debug: %s fields=unavailable\n", event)
		return
	}
	logger.output.Printf("security-scanner: debug: %s %s\n", event, redact.Text(string(data)))
}

type scanProgressEstimator struct {
	lastPercent  int
	analysisSeen bool
}

func newScanProgressEstimator() *scanProgressEstimator {
	return &scanProgressEstimator{}
}

func (e *scanProgressEstimator) observe(message string) (string, int) {
	msg := strings.TrimSpace(message)
	phase, percent := "preparation", 5
	switch {
	case strings.HasPrefix(msg, "archived existing output to "):
		phase, percent = "preparation", 10
	case strings.HasPrefix(msg, "building fixed file inventory"):
		phase, percent = "preparation", 20
	case strings.HasPrefix(msg, "inventory contains "):
		if e.analysisSeen {
			phase, percent = "analysis", 50
		} else {
			phase, percent = "preparation", 35
		}
	case strings.HasPrefix(msg, "using ") && strings.Contains(msg, " model "):
		e.analysisSeen = true
		phase, percent = "analysis", 45
	case strings.HasPrefix(msg, "agent active:"):
		e.analysisSeen = true
		phase, percent = "analysis", max(e.lastPercent+10, 55)
		if percent > 85 {
			percent = 85
		}
	case strings.HasPrefix(msg, "validating and writing scan artifacts"):
		phase, percent = "finalization", 92
	default:
		if e.analysisSeen {
			phase = "analysis"
			percent = max(e.lastPercent, 55)
		} else {
			phase = "preparation"
			percent = max(e.lastPercent, 5)
		}
	}
	if percent < e.lastPercent {
		percent = e.lastPercent
	}
	e.lastPercent = percent
	return phase, percent
}

func writeJSON(value any, stdout, stderr *checkedWriter) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		stderr.Printf("write JSON: %v\n", err)
		return 2
	}
	return 0
}

func runInventory(args []string, stdout, stderr *checkedWriter) int {
	flags := flag.NewFlagSet("inventory", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var excludes stringListFlag
	target := flags.String("target", ".", "repository directory to inventory")
	maxFileBytes := flags.Int64("max-file-bytes", 1024*1024, "maximum reviewable file size")
	flags.Var(&excludes, "exclude", "repository-relative directory to exclude; repeatable")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		stderr.Println("inventory does not accept positional arguments; use --target")
		return 2
	}
	inv, err := scan.BuildInventory(*target, scan.InventoryOptions{MaxFileBytes: *maxFileBytes, Excludes: excludes})
	if err != nil {
		stderr.Printf("inventory failed: %v\n", err)
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(inv); err != nil {
		stderr.Printf("write inventory: %v\n", err)
		return 2
	}
	return 0
}

func printUsage(w *checkedWriter) {
	w.Println("security-scanner scans a repository with an Eino DeepAgent and writes validated reports.")
	w.Println("")
	w.Println("Usage:")
	w.Println("  security-scanner scan [options]")
	w.Println("  security-scanner scan preflight [options]")
	w.Println("  security-scanner inventory [options]")
	w.Println("  security-scanner providers")
	w.Println("  security-scanner bulk-scan INPUT --output-dir PATH [options]")
	w.Println("  security-scanner scans <list|show|rerun|match|compare>")
	w.Println("  security-scanner findings false-positive OCCURRENCE_ID --reason TEXT")
	w.Println("  security-scanner validate [options] FINDING_OR_PROMPT")
	w.Println("  security-scanner patch [options] FINDING_OR_PROMPT")
	w.Println("  security-scanner version")
}

type checkedWriter struct {
	mu     sync.Mutex
	writer io.Writer
	err    error
}

func (w *checkedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	written, err := w.writer.Write(data)
	if err != nil {
		w.err = err
	}
	return written, err
}

func (w *checkedWriter) Printf(format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		w.record(err)
	}
}

func (w *checkedWriter) Println(args ...any) {
	if _, err := fmt.Fprintln(w, args...); err != nil {
		w.record(err)
	}
}

func (w *checkedWriter) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *checkedWriter) record(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err == nil {
		w.err = err
	}
}

type stringListFlag []string

func (f *stringListFlag) String() string { return strings.Join(*f, ",") }

func (f *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("exclude path cannot be empty")
	}
	*f = append(*f, value)
	return nil
}

type pathListFlag []string

func (f *pathListFlag) String() string { return strings.Join(*f, ",") }

func (f *pathListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("path cannot be empty")
	}
	*f = append(*f, value)
	return nil
}
