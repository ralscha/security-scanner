package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type CoverageTracker interface {
	Complete(File) bool
}

type FinalizeOptions struct {
	OutputDir           string
	Provider            string
	Model               string
	StartedAt           time.Time
	TargetMode          string
	TargetRef           string
	TargetPaths         []string
	PreparationDuration time.Duration
	AnalysisDuration    time.Duration
}

func Finalize(inv *Inventory, tracker CoverageTracker, submission Submission, opts FinalizeOptions) (*Result, error) {
	if problems := ValidateSubmission(inv, submission); len(problems) > 0 {
		return nil, fmt.Errorf("invalid submission: %s", strings.Join(problems, "; "))
	}
	if opts.OutputDir == "" {
		return nil, fmt.Errorf("output directory is required")
	}
	findings, err := NormalizeFindings(inv, submission.Findings)
	if err != nil {
		return nil, err
	}
	coverage := buildCoverage(inv, tracker)
	completedAt := time.Now().UTC()
	scanID := newScanID(inv.Root, opts.StartedAt)
	findingsDoc := FindingsDocument{
		SchemaVersion: SchemaVersion,
		ScanID:        scanID,
		ThreatModel:   strings.TrimSpace(submission.ThreatModel),
		Findings:      findings,
		Gaps:          cleanStrings(submission.Gaps),
	}
	status := "completed"
	if coverage.Summary.Unreviewed > 0 {
		status = "completed_with_gaps"
	}
	manifest := ScanManifest{
		SchemaVersion: SchemaVersion,
		ScanID:        scanID,
		Status:        status,
		Target:        inv.Root,
		Provider:      opts.Provider,
		Model:         opts.Model,
		TargetMode:    opts.TargetMode,
		TargetRef:     opts.TargetRef,
		TargetPaths:   append([]string(nil), opts.TargetPaths...),
		StartedAt:     opts.StartedAt.UTC(),
		CompletedAt:   completedAt,
		Artifacts: map[string]string{
			"findings": "findings.json",
			"coverage": "coverage.json",
			"report":   "report.md",
			"sarif":    "results.sarif",
		},
		FilesTotal:    coverage.Summary.Total,
		FilesReviewed: coverage.Summary.Reviewed,
		FindingCount:  len(findings),
		DurationMS:    completedAt.Sub(opts.StartedAt).Milliseconds(),
		Timings: TimingBreakdown{
			PreparationMS: opts.PreparationDuration.Milliseconds(),
			AnalysisMS:    opts.AnalysisDuration.Milliseconds(),
		},
	}
	result := &Result{Manifest: manifest, Findings: findingsDoc, Coverage: coverage, OutDir: opts.OutputDir}
	if err := writeArtifacts(result); err != nil {
		return nil, err
	}
	return result, nil
}

func buildCoverage(inv *Inventory, tracker CoverageTracker) CoverageDocument {
	doc := CoverageDocument{SchemaVersion: SchemaVersion, Files: make([]CoverageFile, 0, len(inv.Files))}
	for _, file := range inv.Files {
		entry := CoverageFile{Path: file.Path}
		switch {
		case !file.Reviewable:
			entry.Outcome = "skipped"
			entry.Reason = file.SkipReason
			doc.Summary.Skipped++
		case tracker != nil && tracker.Complete(file):
			entry.Outcome = "reviewed"
			doc.Summary.Reviewed++
		default:
			entry.Outcome = "unreviewed"
			entry.Reason = "not_read_from_start_to_finish"
			doc.Summary.Unreviewed++
		}
		doc.Files = append(doc.Files, entry)
	}
	doc.Summary.Total = len(doc.Files)
	return doc
}

func writeArtifacts(result *Result) error {
	if err := os.MkdirAll(result.OutDir, 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	artifacts := []struct {
		name string
		data []byte
	}{
		{name: "findings.json", data: mustJSON(result.Findings)},
		{name: "coverage.json", data: mustJSON(result.Coverage)},
		{name: "report.md", data: renderMarkdown(result)},
		{name: "results.sarif", data: mustJSON(buildSARIF(result.Findings))},
		{name: "scan-manifest.json", data: mustJSON(result.Manifest)},
	}
	for _, artifact := range artifacts {
		if err := writeAtomic(filepath.Join(result.OutDir, artifact.name), artifact.data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", artifact.name, err)
		}
	}
	return nil
}

func mustJSON(value any) []byte {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

func writeAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		if removeErr := os.Remove(tempPath); err == nil && removeErr != nil && !os.IsNotExist(removeErr) {
			err = removeErr
		}
	}()
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err == nil {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tempPath, path)
}

func renderMarkdown(result *Result) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "# Security Scan Report\n\n")
	fmt.Fprintf(&out, "- Scan ID: `%s`\n", result.Manifest.ScanID)
	fmt.Fprintf(&out, "- Status: `%s`\n", result.Manifest.Status)
	fmt.Fprintf(&out, "- Model: `%s/%s`\n", markdownText(result.Manifest.Provider), markdownText(result.Manifest.Model))
	fmt.Fprintf(&out, "- Completed: `%s`\n", result.Manifest.CompletedAt.Format(time.RFC3339))
	fmt.Fprintf(&out, "- Coverage: %d reviewed, %d unreviewed, %d skipped, %d total\n\n",
		result.Coverage.Summary.Reviewed, result.Coverage.Summary.Unreviewed,
		result.Coverage.Summary.Skipped, result.Coverage.Summary.Total)

	fmt.Fprintf(&out, "## Threat Model\n\n%s\n\n", markdownText(result.Findings.ThreatModel))
	fmt.Fprintf(&out, "## Findings\n\n")
	if len(result.Findings.Findings) == 0 {
		fmt.Fprintf(&out, "No validated findings were reported.\n\n")
	}
	for _, finding := range result.Findings.Findings {
		fmt.Fprintf(&out, "### %s: %s\n\n", finding.ID, markdownText(finding.Title))
		fmt.Fprintf(&out, "**Severity:** %s | **Confidence:** %s", finding.Severity, finding.Confidence)
		if len(finding.CWEIDs) > 0 {
			fmt.Fprintf(&out, " | **CWE:** %s", markdownText(strings.Join(finding.CWEIDs, ", ")))
		}
		fmt.Fprintf(&out, "\n\n%s\n\n", markdownText(finding.Summary))
		writeReportField(&out, "Impact", finding.Impact)
		writeReportField(&out, "Evidence", finding.Evidence)
		writeReportField(&out, "Attack Path", finding.AttackPath)
		writeReportField(&out, "Remediation", finding.Remediation)
		fmt.Fprintf(&out, "**Locations**\n\n")
		for _, loc := range finding.Locations {
			fmt.Fprintf(&out, "- `%s:%d-%d` (%s)\n", markdownCode(loc.Path), loc.StartLine, loc.EndLine, markdownText(loc.Role))
		}
		fmt.Fprintln(&out)
	}

	if len(result.Findings.Gaps) > 0 || result.Coverage.Summary.Unreviewed > 0 {
		fmt.Fprintf(&out, "## Coverage Gaps\n\n")
		for _, gap := range result.Findings.Gaps {
			fmt.Fprintf(&out, "- %s\n", markdownText(gap))
		}
		for _, file := range result.Coverage.Files {
			if file.Outcome == "unreviewed" {
				fmt.Fprintf(&out, "- `%s`: %s\n", markdownCode(file.Path), markdownText(file.Reason))
			}
		}
		fmt.Fprintln(&out)
	}

	fmt.Fprintf(&out, "## Skipped Files\n\n")
	skipped := 0
	for _, file := range result.Coverage.Files {
		if file.Outcome == "skipped" {
			skipped++
			fmt.Fprintf(&out, "- `%s`: %s\n", markdownCode(file.Path), markdownText(file.Reason))
		}
	}
	if skipped == 0 {
		fmt.Fprintln(&out, "None.")
	}
	return out.Bytes()
}

func writeReportField(out *bytes.Buffer, label, value string) {
	fmt.Fprintf(out, "**%s**\n\n%s\n\n", label, markdownText(value))
}

func markdownText(value string) string {
	value = strings.TrimSpace(value)
	value = html.EscapeString(value)
	return strings.ReplaceAll(value, "\x00", "")
}

func markdownCode(value string) string {
	return strings.ReplaceAll(markdownText(value), "`", "'")
}

func cleanStrings(values []string) []string {
	clean := make([]string, 0, len(values))
	seen := make(map[string]struct{})
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		clean = append(clean, value)
	}
	return clean
}

func newScanID(root string, started time.Time) string {
	sum := sha256.Sum256([]byte(root + "\n" + started.UTC().Format(time.RFC3339Nano)))
	return fmt.Sprintf("scan-%s-%x", started.UTC().Format("20060102T150405Z"), sum[:4])
}

func sourceSnippet(root, path string, start, end int) string {
	joined := filepath.Join(root, filepath.FromSlash(path))
	info, err := os.Lstat(joined)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return ""
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || escapesRoot(rel) {
		return ""
	}
	content, err := os.ReadFile(resolved)
	if err != nil {
		return ""
	}
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	if start < 1 || start > len(lines) {
		return ""
	}
	if end < start {
		end = start
	}
	if end > len(lines) {
		end = len(lines)
	}
	if end-start > 11 {
		end = start + 11
	}
	return strings.Join(lines[start-1:end], "\n")
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

func buildSARIF(doc FindingsDocument) sarifLog {
	rules := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(doc.Findings))
	for _, finding := range doc.Findings {
		ruleID := "SECURITY"
		if len(finding.CWEIDs) > 0 {
			ruleID = finding.CWEIDs[0]
		}
		rules[ruleID] = sarifRule{ID: ruleID, Name: ruleID, ShortDescription: sarifMessage{Text: finding.Title}}
		locations := make([]sarifLocation, 0, len(finding.Locations))
		for _, loc := range finding.Locations {
			locations = append(locations, sarifLocation{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: loc.Path},
				Region:           sarifRegion{StartLine: loc.StartLine, EndLine: loc.EndLine},
			}})
		}
		results = append(results, sarifResult{
			RuleID:              ruleID,
			Level:               sarifLevel(finding.Severity),
			Message:             sarifMessage{Text: finding.Title + ": " + finding.Summary},
			Locations:           locations,
			PartialFingerprints: map[string]string{"security-scanner/finding-id": finding.ID},
		})
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	return sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{
		Tool: sarifTool{Driver: sarifDriver{Name: "security-scanner", Rules: ruleList}}, Results: results,
	}}}
}

func sarifLevel(severity Severity) string {
	switch severity {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
