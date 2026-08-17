package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"security-scanner/internal/history"
	linearapi "security-scanner/internal/linear"
	"security-scanner/internal/publication"
	"security-scanner/internal/scan"
)

func TestInventoryCommand(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"inventory", "--target", root}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var inv scan.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Files) != 1 || inv.Files[0].Path != "main.go" {
		t.Fatalf("unexpected inventory: %#v", inv)
	}
}

func TestInventoryFailureUsesRuntimeExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"inventory", "--target", filepath.Join(t.TempDir(), "missing")}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestOutputFailureUsesRuntimeExitCode(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"help"}, errorWriter{}, &stderr); code != 2 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestScanTerminalReportingFailureIsNonfatal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	code := run([]string{"scan", "--dry-run", "--target", root, "--provider", "ollama", "--model", "test", "--auth", "none"}, &stdout, errorWriter{})
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("dry-run output is invalid: %s", stdout.String())
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != version {
		t.Fatalf("version = %q, want %q", got, version)
	}
}

func TestExitCodeForSignal(t *testing.T) {
	if got := exitCodeForSignal(os.Interrupt); got != 130 {
		t.Fatalf("interrupt exit = %d", got)
	}
	if got := exitCodeForSignal(syscall.SIGTERM); got != 143 {
		t.Fatalf("terminate exit = %d", got)
	}
}

func TestScanRequiresAPIKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("SECURITY_SCANNER_API_KEY", "")
	t.Setenv("SECURITY_SCANNER_PROVIDER", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--api-key=", "--target", t.TempDir()}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("API key is required for provider openai")) {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestScanDryRunDoesNotCallModel(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--dry-run", "--target", root, "--api-key", "not-used", "--path", "main.go"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	var payload struct {
		DryRun bool `json:"dry_run"`
		Scan   struct {
			Inventory scan.Inventory `json:"inventory"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.DryRun || len(payload.Scan.Inventory.Files) != 1 {
		t.Fatalf("unexpected dry-run payload: %s", stdout.String())
	}
}

func TestScanVerboseDiagnosticsStayOnStderr(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_LOG_LEVEL", "")
	t.Setenv("LOG_LEVEL", "")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan", "--dry-run", "--quiet", "--verbose", "--target", root,
		"--provider", "ollama", "--model", "test-model", "--auth", "none",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("verbose diagnostics corrupted stdout: %s", stdout.String())
	}
	for _, event := range []string{"scan.configuration", "scan.target_resolved", "scan.preflight.completed"} {
		if !strings.Contains(stderr.String(), "security-scanner: debug: "+event) {
			t.Errorf("missing %s diagnostic:\n%s", event, stderr.String())
		}
	}
}

func TestScanJSONProgressEmitsStructuredEvents(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_LOG_LEVEL", "")
	t.Setenv("LOG_LEVEL", "")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan", "--dry-run", "--quiet", "--json-progress", "--target", root,
		"--provider", "ollama", "--model", "test-model", "--auth", "none",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("JSON progress corrupted stdout: %s", stdout.String())
	}
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		t.Fatalf("expected at least one JSON progress line, got %q", stderr.String())
	}
	foundProgress := false
	lastPercent := 0
	lastStatus := ""
	lastPhase := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event struct {
			Event     string `json:"event"`
			Timestamp string `json:"timestamp"`
			Message   string `json:"message"`
			Phase     string `json:"phase"`
			Percent   int    `json:"percent"`
			Status    string `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("invalid JSON progress line %q: %v", line, err)
		}
		if event.Event == "scan.progress" {
			foundProgress = true
		}
		if event.Timestamp == "" || event.Message == "" {
			t.Fatalf("incomplete progress event: %#v", event)
		}
		if event.Phase == "" || event.Percent <= 0 || event.Percent > 100 {
			t.Fatalf("progress event missing phase/percent metadata: %#v", event)
		}
		lastPercent = event.Percent
		lastStatus = event.Status
		lastPhase = event.Phase
	}
	if !foundProgress {
		t.Fatalf("missing scan.progress events in stderr: %s", stderr.String())
	}
	if lastPercent != 100 || lastStatus != "completed" || lastPhase != "completed" {
		t.Fatalf("expected terminal completion event, got phase=%q percent=%d status=%q", lastPhase, lastPercent, lastStatus)
	}
}

func TestScanJSONProgressFailureEmitsTerminalEvent(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_LOG_LEVEL", "")
	t.Setenv("LOG_LEVEL", "")
	missing := filepath.Join(t.TempDir(), "missing")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan", "--quiet", "--json-progress", "--target", missing,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if len(lines) == 0 {
		t.Fatalf("expected JSON progress output on failure, got %q", stderr.String())
	}
	foundTerminal := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event struct {
			Event   string `json:"event"`
			Phase   string `json:"phase"`
			Percent int    `json:"percent"`
			Status  string `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event.Event == "scan.progress" && event.Phase == "completed" && event.Percent == 100 && event.Status == "failed" {
			foundTerminal = true
			break
		}
	}
	if !foundTerminal {
		t.Fatalf("missing terminal failure progress event in stderr: %s", stderr.String())
	}
}

func TestScanJSONProgressStrictRequiresJSONProgress(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--json-progress-strict", "--target", t.TempDir()}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--json-progress") {
		t.Fatalf("missing actionable strict-mode dependency error: %s", stderr.String())
	}
}

func TestScanJSONProgressStrictEmitsOnlyJSONOnSuccess(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_LOG_LEVEL", "debug")
	t.Setenv("LOG_LEVEL", "")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan", "--dry-run", "--quiet", "--json-progress", "--json-progress-strict", "--target", root,
		"--provider", "ollama", "--model", "test-model", "--auth", "none", "--verbose",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("strict JSON progress corrupted stdout: %s", stdout.String())
	}
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		t.Fatalf("expected strict JSON progress output, got %q", stderr.String())
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event struct {
			Event string `json:"event"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("strict mode emitted non-JSON stderr line %q: %v", line, err)
		}
		if event.Event != "scan.progress" {
			t.Fatalf("unexpected strict-mode event: %#v", event)
		}
	}
}

func TestScanJSONProgressStrictEmitsOnlyJSONOnFailure(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_LOG_LEVEL", "debug")
	t.Setenv("LOG_LEVEL", "")
	missing := filepath.Join(t.TempDir(), "missing")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan", "--quiet", "--json-progress", "--json-progress-strict", "--target", missing,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		t.Fatalf("expected strict JSON progress output on failure, got %q", stderr.String())
	}
	foundTerminal := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event struct {
			Event   string `json:"event"`
			Status  string `json:"status"`
			Percent int    `json:"percent"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("strict mode emitted non-JSON stderr line %q: %v", line, err)
		}
		if event.Event != "scan.progress" {
			t.Fatalf("unexpected strict-mode event: %#v", event)
		}
		if event.Status == "failed" && event.Percent == 100 {
			foundTerminal = true
		}
	}
	if !foundTerminal {
		t.Fatalf("missing strict-mode terminal failure event: %s", stderr.String())
	}
}

func TestScanProgressEstimatorMonotonicPhases(t *testing.T) {
	estimator := newScanProgressEstimator()
	steps := []struct {
		message    string
		wantPhase  string
		minimumPct int
		maximumPct int
	}{
		{message: "building fixed file inventory", wantPhase: "preparation", minimumPct: 20, maximumPct: 20},
		{message: "inventory contains 4 files", wantPhase: "preparation", minimumPct: 35, maximumPct: 35},
		{message: "using ollama model test-model", wantPhase: "analysis", minimumPct: 45, maximumPct: 45},
		{message: "agent active: discovery", wantPhase: "analysis", minimumPct: 55, maximumPct: 85},
		{message: "validating and writing scan artifacts", wantPhase: "finalization", minimumPct: 92, maximumPct: 92},
	}
	last := 0
	for _, step := range steps {
		phase, pct := estimator.observe(step.message)
		if phase != step.wantPhase {
			t.Fatalf("phase for %q = %q, want %q", step.message, phase, step.wantPhase)
		}
		if pct < step.minimumPct || pct > step.maximumPct {
			t.Fatalf("percent for %q = %d, want in [%d,%d]", step.message, pct, step.minimumPct, step.maximumPct)
		}
		if pct < last {
			t.Fatalf("progress regressed from %d to %d on %q", last, pct, step.message)
		}
		last = pct
	}
}

func TestVerboseDiagnosticsCanBeEnabledByEnvironment(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_LOG_LEVEL", "debug")
	t.Setenv("LOG_LEVEL", "")
	var output bytes.Buffer
	writer := &checkedWriter{writer: &output}
	logger := newDiagnosticLogger(false, writer)
	logger.Log("scan.test", map[string]any{"ok": true})
	if !logger.Enabled() || !strings.Contains(output.String(), "security-scanner: debug: scan.test") {
		t.Fatalf("environment did not enable diagnostics: %q", output.String())
	}
}

func TestScanRejectsConflictingTargetSelectors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--target", t.TempDir(), "--path", ".", "--working-tree"}, &stdout, &stderr)
	if code != 2 || !bytes.Contains(stderr.Bytes(), []byte("mutually exclusive")) {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestProvidersCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"providers"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, provider := range []string{"openai", "azure-openai", "openai-compatible", "openrouter", "fireworks", "anthropic", "gemini", "ollama", "ark"} {
		if !bytes.Contains(stdout.Bytes(), []byte(provider)) {
			t.Errorf("provider output does not contain %q:\n%s", provider, stdout.String())
		}
	}
}

func TestHelpListsRoadmapCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, command := range []string{"scan preflight", "bulk-scan", "scans [list|show|logs|rerun|match|compare]", "findings list", "findings false-positive", "publish scan", "validate", "patch"} {
		if !strings.Contains(stdout.String(), command) {
			t.Errorf("help does not contain %q:\n%s", command, stdout.String())
		}
	}
}

func TestPreflightJSONDoesNotCallModel(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "preflight", "--target", root, "--provider", "ollama", "--model", "not-installed", "--auth", "none", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || !result.OK {
		t.Fatalf("unexpected preflight: %s, %v", stdout.String(), err)
	}
}

func TestDryRunAndPreflightPrepareKnowledgeBaseWithoutModelCalls(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kb := filepath.Join(t.TempDir(), "guide.md")
	if err := os.WriteFile(kb, []byte("Use least privilege.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", "--dry-run", "--target", root, "--provider", "ollama", "--model", "not-installed", "--auth", "none", "--knowledge-base", kb},
		{"scan", "preflight", "--target", root, "--provider", "ollama", "--model", "not-installed", "--auth", "none", "--knowledge-base", kb, "--json"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("%v exit %d: %s", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "knowledge") {
			t.Fatalf("knowledge-base metadata missing from %v: %s", args, stdout.String())
		}
	}
}

func TestPreflightJSONRedactsCredentialsInTargetErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "api_key=super-secret-value")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "preflight", "--target", missing, "--json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d: stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "super-secret-value") || !strings.Contains(stdout.String(), "[redacted]") {
		t.Fatalf("credential escaped into JSON preflight error: %s", stdout.String())
	}
}

func TestLifecycleAndBulkCommandsValidateArguments(t *testing.T) {
	for _, args := range [][]string{{"bulk-scan"}, {"findings", "false-positive", "F-1"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("%v exit = %d, stderr = %s", args, code, stderr.String())
		}
	}
}

func TestBulkScanAcceptsInputBeforeAfterOrWithinFlags(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.csv")
	output := t.TempDir()
	for _, args := range [][]string{
		{"bulk-scan", missing, "--output-dir", output},
		{"bulk-scan", "--output-dir", output, missing},
		{"bulk-scan", "--input", missing, "--output-dir", output},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "read bulk input") {
			t.Errorf("%v: exit=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func TestBulkScanRejectsMultipleInputSources(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"bulk-scan", "repos.csv", "--input", "other.csv", "--output-dir", t.TempDir()}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "exactly one input") {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
}

func TestFindingsFalsePositiveRequiresReason(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"findings", "false-positive", "scan-1:F-ABC"}, &stdout, &stderr)
	if code != 2 || !bytes.Contains(stderr.Bytes(), []byte("requires --reason")) {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestFindingsListShowsSavedRepositoryFindings(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SECURITY_SCANNER_STATE_DIR", state)
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory, err := scan.BuildInventory(target, scan.InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scan.Finalize(inventory, nil, scan.Submission{
		ThreatModel: "Untrusted callers can reach the application.",
		Findings: []scan.FindingDraft{{
			Title: "Missing authorization", Severity: scan.SeverityHigh, Confidence: scan.ConfidenceHigh,
			CWEIDs: []string{"CWE-862"}, Summary: "The operation is not authorized.", Impact: "Unauthorized access.",
			Evidence: "app.go exposes the operation.", Remediation: "Add authorization.", AttackPath: "A caller invokes the operation.",
			Locations: []scan.Location{{Path: "app.go", StartLine: 1, Role: "root_control"}},
		}},
	}, scan.FinalizeOptions{ScanID: scan.AllocateScanID(target, time.Unix(100, 0)), OutputDir: filepath.Join(state, "scan"), Provider: "test", Model: "test", StartedAt: time.Unix(100, 0)})
	if err != nil {
		t.Fatal(err)
	}
	store, err := history.DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(result); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"findings", "list", "--target", target, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var listed struct {
		Repository string                      `json:"repository"`
		Findings   []history.RepositoryFinding `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Repository != target || len(listed.Findings) != 1 || listed.Findings[0].Title != "Missing authorization" || !listed.Findings[0].ConfirmedInLatestScan {
		t.Fatalf("unexpected findings list: %s", stdout.String())
	}
	prefix := result.Manifest.ScanID[:len(result.Manifest.ScanID)-4]
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scans", "logs", prefix, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("logs exit %d: %s", code, stderr.String())
	}
	var log history.ScanLog
	if err := json.Unmarshal(stdout.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.ScanID != result.Manifest.ScanID || len(log.Events) != 1 || log.Events[0].Event != "scan.completed" {
		t.Fatalf("unexpected saved scan log: %s", stdout.String())
	}
	resolved, resolvedTarget, err := resolveReviewInput(prefix+":"+result.Findings.Findings[0].ID, "")
	if err != nil || resolvedTarget != target || !strings.Contains(resolved, "Missing authorization") {
		t.Fatalf("occurrence prefix did not resolve: target=%q input=%q err=%v", resolvedTarget, resolved, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"findings", "false-positive", prefix + ":" + result.Findings.Findings[0].ID, "--reason", "covered elsewhere"}, &stdout, &stderr); code != 0 {
		t.Fatalf("triage exit %d: %s", code, stderr.String())
	}
	var decision struct {
		OccurrenceID string `json:"occurrence_id"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decision); err != nil || decision.OccurrenceID != result.Manifest.ScanID+":"+result.Findings.Findings[0].ID {
		t.Fatalf("triage did not canonicalize occurrence: %s, %v", stdout.String(), err)
	}
}

func TestSavedScanShortcutsUseLatestCurrentRepositoryScans(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SECURITY_SCANNER_STATE_DIR", state)
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "app.go"), []byte("package app\n\nfunc run() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(target)
	first := saveShortcutScan(t, state, target, time.Unix(100, 0), "First finding")
	second := saveShortcutScan(t, state, target, time.Unix(200, 0), "Second finding")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"scans", "--json"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), second.Manifest.ScanID) {
		t.Fatalf("default scans list exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scans", "show"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), second.Manifest.ScanID) {
		t.Fatalf("default scans show exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scans", "logs", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("default scans logs exit=%d stderr=%s", code, stderr.String())
	}
	var log history.ScanLog
	if err := json.Unmarshal(stdout.Bytes(), &log); err != nil || log.ScanID != second.Manifest.ScanID {
		t.Fatalf("latest log = %s, %v", stdout.String(), err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scans", "compare", "--json"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), first.Manifest.ScanID) || !strings.Contains(stdout.String(), second.Manifest.ScanID) {
		t.Fatalf("default compare exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"findings", "--json"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "Second finding") {
		t.Fatalf("default findings list exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestPublishScanDryRunUsesSealedHistoryWithoutLinearCredentials(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SECURITY_SCANNER_STATE_DIR", state)
	t.Setenv("CODEX_SECURITY_LINEAR_API_KEY", "")
	t.Setenv("CODEX_SECURITY_LINEAR_TEAM", "")
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(target)
	saved := saveShortcutScan(t, state, target, time.Unix(300, 0), "Publish finding")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"publish", "scan", saved.OutDir, "--to", "linear", "--linear-team", "team-1", "--dry-run", "--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var result publication.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.DryRun || result.ScanID != saved.Manifest.ScanID || len(result.Issues) != 1 || result.Issues[0].Priority != 2 {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(filepath.Join(state, "publications")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run wrote publication state: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"publish", "scan", saved.Manifest.ScanID, "--to", "linear", "--linear-team", "team-1"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "requires --linear-api-key") {
		t.Fatalf("missing-key exit=%d stderr=%s", code, stderr.String())
	}
}

func TestLinearPatchIntakeValidationAndRendering(t *testing.T) {
	t.Setenv("CODEX_SECURITY_LINEAR_API_KEY", "")
	t.Setenv("LINEAR_API_KEY", "")
	t.Setenv("LINEAR_ACCESS_TOKEN", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"patch", "--linear-issue", "SEC-123", "--target", t.TempDir()}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "Linear access requires") {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	input := renderLinearPatchInput([]linearapi.Issue{{
		Identifier: "SEC-123", URL: "https://linear.app/acme/issue/SEC-123/title",
		Title: "Fix the parser", Description: "The request may be inaccurate.",
	}})
	for _, expected := range []string{"untrusted remediation requests", "SEC-123", "Fix the parser", "may be inaccurate"} {
		if !strings.Contains(input, expected) {
			t.Fatalf("rendered input missing %q: %s", expected, input)
		}
	}
}

func saveShortcutScan(t *testing.T, state, target string, started time.Time, title string) *scan.Result {
	t.Helper()
	inventory, err := scan.BuildInventory(target, scan.InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scan.Finalize(inventory, nil, scan.Submission{
		ThreatModel: "Untrusted callers can reach the application.",
		Findings: []scan.FindingDraft{{
			Title: title, Severity: scan.SeverityHigh, Confidence: scan.ConfidenceHigh,
			CWEIDs: []string{"CWE-20"}, Summary: "The input is not validated.", Impact: "Unsafe behavior.",
			Evidence: "app.go processes the input.", Remediation: "Validate the input.", AttackPath: "A caller supplies input.",
			Locations: []scan.Location{{Path: "app.go", StartLine: 1, Role: "sink"}},
		}},
	}, scan.FinalizeOptions{
		ScanID: scan.AllocateScanID(target, started), OutputDir: filepath.Join(state, "scan-"+started.UTC().Format("150405")),
		Provider: "test", Model: "test", StartedAt: started, TargetMode: "repository",
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := history.DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestValidateRequiresInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"validate"}, &stdout, &stderr)
	if code != 2 || !bytes.Contains(stderr.Bytes(), []byte("FINDING_OR_PROMPT")) {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestWriteNewFileDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proposal.json")
	if err := writeNewFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFile(path, []byte("second")); err == nil {
		t.Fatal("expected existing export to be preserved")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first" {
		t.Fatalf("export was overwritten: %q", data)
	}
}

func TestRerunScanArgsPreserveSavedConfiguration(t *testing.T) {
	record := history.Record{
		ScanID: "scan-1", Target: `C:\repo`, Provider: "fireworks", Model: "accounts/fireworks/models/test",
		TargetMode: "path", TargetPaths: []string{"cmd", "internal/auth"},
		LaunchConfig: &scan.LaunchConfiguration{
			AuthMode: "env", BaseURL: "https://example.test/v1", MaxOutputTokens: 4096,
			UserContext: "internet-facing", Excludes: []string{"vendor"}, MaxFileBytes: 2048,
			MaxIterations: 12, MaxAgentConcurrency: 3, RequestTimeout: "2m0s", MaxDuration: "15m0s",
			FailOnSeverity: "high", ScanPrompt: "prioritize auth surfaces", FollowUpPrompt: "cross-check taint routes",
		},
	}
	args, err := rerunScanArgs(record, true)
	if err != nil {
		t.Fatal(err)
	}
	for flag, value := range map[string]string{
		"--provider": "fireworks", "--auth": "env", "--base-url": "https://example.test/v1",
		"--max-output-tokens": "4096", "--context": "internet-facing", "--exclude": "vendor",
		"--max-file-bytes": "2048", "--max-iterations": "12", "--max-agent-concurrency": "3",
		"--request-timeout": "2m0s", "--max-duration": "15m0s", "--fail-on-severity": "high",
		"--scan-prompt": "prioritize auth surfaces", "--follow-up-prompt": "cross-check taint routes",
	} {
		if !containsFlagValue(args, flag, value) {
			t.Errorf("rerun args do not contain %s %q: %#v", flag, value, args)
		}
	}
	if !containsFlagValue(args, "--path", "cmd") || !containsFlagValue(args, "--path", "internal/auth") || !slicesContain(args, "--verbose") {
		t.Fatalf("rerun targeting or verbose setting was lost: %#v", args)
	}
}

func TestRerunScanArgsDoNotPersistExplicitAPIKey(t *testing.T) {
	_, err := rerunScanArgs(history.Record{
		Target: t.TempDir(), Provider: "openai", Model: "test",
		LaunchConfig: &scan.LaunchConfiguration{AuthMode: "auto", RequiresExplicitAPIKey: true},
	}, false)
	if err == nil || !strings.Contains(err.Error(), "API keys are not stored") {
		t.Fatalf("expected actionable API-key rerun error, got %v", err)
	}
}

func containsFlagValue(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func slicesContain(values []string, expected string) bool {
	return slices.Contains(values, expected)
}

func TestResolvePromptOverride(t *testing.T) {
	value, err := resolvePromptOverride("  inline guidance  ", "", "scan")
	if err != nil || value != "inline guidance" {
		t.Fatalf("inline prompt resolution failed: value=%q err=%v", value, err)
	}

	file := filepath.Join(t.TempDir(), "prompt.txt")
	if err := os.WriteFile(file, []byte("\n  file guidance\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err = resolvePromptOverride("", file, "follow-up")
	if err != nil || value != "file guidance" {
		t.Fatalf("file prompt resolution failed: value=%q err=%v", value, err)
	}

	if _, err := resolvePromptOverride("inline", file, "scan"); err == nil || !strings.Contains(err.Error(), "either --scan-prompt or --scan-prompt-file") {
		t.Fatalf("expected mutually-exclusive prompt error, got %v", err)
	}

	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("\n \t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePromptOverride("", empty, "follow-up"); err == nil || !strings.Contains(err.Error(), "--follow-up-prompt-file is empty") {
		t.Fatalf("expected empty-file prompt error, got %v", err)
	}

	if _, err := resolvePromptOverride("bad\x00prompt", "", "scan"); err == nil || !strings.Contains(err.Error(), "cannot contain NUL") {
		t.Fatalf("expected NUL prompt error, got %v", err)
	}

	invalidUTF8 := filepath.Join(t.TempDir(), "invalid.txt")
	if err := os.WriteFile(invalidUTF8, []byte{0xff, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePromptOverride("", invalidUTF8, "follow-up"); err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
		t.Fatalf("expected UTF-8 prompt error, got %v", err)
	}

	if _, err := resolvePromptOverride("", t.TempDir(), "scan"); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected non-regular prompt error, got %v", err)
	}
}

func TestPreflightAcceptsPromptOverridesFromFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanPromptFile := filepath.Join(t.TempDir(), "scan-prompt.txt")
	followUpPromptFile := filepath.Join(t.TempDir(), "followup-prompt.txt")
	if err := os.WriteFile(scanPromptFile, []byte("focus auth boundaries"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(followUpPromptFile, []byte("challenge dataflow assumptions"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan", "preflight", "--target", root, "--provider", "ollama", "--model", "not-installed", "--auth", "none", "--json",
		"--scan-prompt-file", scanPromptFile, "--follow-up-prompt-file", followUpPromptFile,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || !result.OK {
		t.Fatalf("unexpected preflight result: stdout=%s err=%v", stdout.String(), err)
	}
}
