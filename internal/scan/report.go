package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"security-scanner/internal/output"
)

type CoverageTracker interface {
	Complete(File) bool
}

type FinalizeOptions struct {
	ScanID              string
	OutputDir           string
	Provider            string
	Model               string
	StartedAt           time.Time
	TargetMode          string
	TargetRef           string
	TargetPaths         []string
	PreparationDuration time.Duration
	AnalysisDuration    time.Duration
	OutputGuard         *output.Guard
	LaunchConfig        *LaunchConfiguration
	Activity            []ActivityEvent
}

func Finalize(inv *Inventory, tracker CoverageTracker, submission Submission, opts FinalizeOptions) (*Result, error) {
	if err := ValidateScanID(opts.ScanID); err != nil {
		return nil, err
	}
	if problems := ValidateSubmission(inv, submission); len(problems) > 0 {
		return nil, &InvalidSubmissionError{Problems: problems}
	}
	if opts.OutputDir == "" {
		return nil, fmt.Errorf("output directory is required")
	}
	if err := VerifyInventory(inv); err != nil {
		return nil, err
	}
	findings, err := NormalizeFindings(inv, submission.Findings)
	if err != nil {
		return nil, err
	}
	if err := VerifyInventory(inv); err != nil {
		return nil, err
	}
	coverage := buildCoverage(inv, tracker)
	completedAt := time.Now().UTC()
	scanID := opts.ScanID
	coverage.ScanID = scanID
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
			"log":      "scan-log.jsonl",
		},
		FilesTotal:    coverage.Summary.Total,
		FilesReviewed: coverage.Summary.Reviewed,
		FindingCount:  len(findings),
		DurationMS:    completedAt.Sub(opts.StartedAt).Milliseconds(),
		Timings: TimingBreakdown{
			PreparationMS: opts.PreparationDuration.Milliseconds(),
			AnalysisMS:    opts.AnalysisDuration.Milliseconds(),
		},
		LaunchConfig: cloneLaunchConfiguration(opts.LaunchConfig),
	}
	activity := append([]ActivityEvent(nil), opts.Activity...)
	activity = append(activity, ActivityEvent{Timestamp: completedAt, Event: "scan.completed", Message: status})
	result := &Result{Manifest: manifest, Findings: findingsDoc, Coverage: coverage, Activity: activity, OutDir: opts.OutputDir}
	guard := opts.OutputGuard
	if guard == nil {
		prepared, err := output.PreparePrivateDir(opts.OutputDir)
		if err != nil {
			return nil, fmt.Errorf("prepare private output directory: %w", err)
		}
		guard = prepared
	}
	if err := writeArtifacts(result, guard); err != nil {
		return nil, err
	}
	return result, nil
}

func cloneLaunchConfiguration(config *LaunchConfiguration) *LaunchConfiguration {
	if config == nil {
		return nil
	}
	clone := *config
	clone.Excludes = append([]string(nil), config.Excludes...)
	clone.KnowledgeBasePaths = append([]string(nil), config.KnowledgeBasePaths...)
	return &clone
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

func writeArtifacts(result *Result, guard *output.Guard) error {
	artifacts := []struct {
		name string
		data []byte
	}{
		{name: "findings.json", data: mustJSON(result.Findings)},
		{name: "coverage.json", data: mustJSON(result.Coverage)},
		{name: "report.md", data: renderMarkdown(result)},
		{name: "results.sarif", data: mustJSON(buildSARIF(result.Findings, result.Coverage))},
		{name: "scan-log.jsonl", data: activityJSONL(result.Activity)},
	}
	result.Manifest.ArtifactDigests = make(map[string]string, len(artifacts)-1)
	for _, artifact := range artifacts {
		// The activity journal remains operational after canonical finalization
		// (for example, to record a post-scan pass), so it is deliberately not
		// part of the immutable result seal.
		if artifact.name == "scan-log.jsonl" {
			continue
		}
		digest := sha256.Sum256(artifact.data)
		result.Manifest.ArtifactDigests[artifact.name] = fmt.Sprintf("sha256:%x", digest[:])
	}
	artifacts = append(artifacts, struct {
		name string
		data []byte
	}{name: "scan-manifest.json", data: mustJSON(result.Manifest)})
	for _, artifact := range artifacts {
		if err := guard.Validate(); err != nil {
			return fmt.Errorf("validate private output before writing %s: %w", artifact.name, err)
		}
		if err := output.WritePrivateFileAtomic(guard, artifact.name, artifact.data); err != nil {
			return fmt.Errorf("write %s: %w", artifact.name, err)
		}
	}
	return nil
}

func activityJSONL(events []ActivityEvent) []byte {
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			panic(err)
		}
	}
	return data.Bytes()
}

func mustJSON(value any) []byte {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
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

func AllocateScanID(root string, started time.Time) string {
	sum := sha256.Sum256([]byte(root + "\n" + started.UTC().Format(time.RFC3339Nano)))
	return fmt.Sprintf("scan-%s-%x", started.UTC().Format("20060102T150405Z"), sum[:4])
}

var scanIDPattern = regexp.MustCompile(`^scan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)

func ValidateScanID(scanID string) error {
	if !scanIDPattern.MatchString(scanID) {
		return fmt.Errorf("scan ID is empty or malformed")
	}
	return nil
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
	Tool              sarifTool              `json:"tool"`
	AutomationDetails sarifAutomationDetails `json:"automationDetails"`
	Results           []sarifResult          `json:"results"`
	Invocations       []sarifInvocation      `json:"invocations"`
	Properties        map[string]string      `json:"properties,omitempty"`
}

type sarifAutomationDetails struct {
	ID string `json:"id"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
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
	ID               string                  `json:"id"`
	Name             string                  `json:"name"`
	ShortDescription sarifMessage            `json:"shortDescription"`
	FullDescription  sarifMessage            `json:"fullDescription"`
	Help             sarifMultiformatMessage `json:"help"`
	Properties       map[string]any          `json:"properties"`
}

type sarifMultiformatMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	Message          *sarifMessage         `json:"message,omitempty"`
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

func buildSARIF(doc FindingsDocument, coverage CoverageDocument) sarifLog {
	findingsByRule := make(map[string][]Finding)
	for _, finding := range doc.Findings {
		ruleID := sarifRuleID(finding)
		findingsByRule[ruleID] = append(findingsByRule[ruleID], finding)
	}
	ruleIDs := make([]string, 0, len(findingsByRule))
	for ruleID := range findingsByRule {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(ruleIDs))
	ruleIndexes := make(map[string]int, len(ruleIDs))
	for index, ruleID := range ruleIDs {
		ruleIndexes[ruleID] = index
		rules = append(rules, buildSARIFRule(ruleID, findingsByRule[ruleID]))
	}
	results := make([]sarifResult, 0, len(doc.Findings))
	for _, finding := range doc.Findings {
		ruleID := sarifRuleID(finding)
		fingerprints := map[string]string{"security-scanner/finding-id": finding.ID}
		if finding.Fingerprint != "" {
			fingerprints["security-scanner/v1"] = finding.Fingerprint
		}
		results = append(results, sarifResult{
			RuleID:              ruleID,
			RuleIndex:           ruleIndexes[ruleID],
			Level:               sarifLevel(finding.Severity),
			Message:             sarifMessage{Text: sarifFindingMessage(finding)},
			Locations:           sarifLocations(finding),
			PartialFingerprints: fingerprints,
			Properties: map[string]any{
				"confidence": string(finding.Confidence), "findingId": finding.ID,
				"severity": string(finding.Severity), "cwe": append([]string(nil), finding.CWEIDs...),
			},
		})
	}
	complete := coverage.Summary.Unreviewed == 0
	invocation := sarifInvocation{ExecutionSuccessful: complete}
	coverageState := "complete"
	if !complete {
		coverageState = "incomplete"
		reasons := make(map[string]struct{})
		for _, file := range coverage.Files {
			if file.Outcome == "unreviewed" && strings.TrimSpace(file.Reason) != "" {
				reasons[strings.TrimSpace(file.Reason)] = struct{}{}
			}
		}
		if len(reasons) == 0 {
			reasons["Scan coverage is incomplete; results may be incomplete."] = struct{}{}
		}
		ordered := make([]string, 0, len(reasons))
		for reason := range reasons {
			ordered = append(ordered, reason)
		}
		sort.Strings(ordered)
		for _, reason := range ordered {
			invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, sarifNotification{
				Level: "warning", Message: sarifMessage{Text: reason},
			})
		}
	}
	return sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{
		Tool:              sarifTool{Driver: sarifDriver{Name: "security-scanner", Rules: rules}},
		AutomationDetails: sarifAutomationDetails{ID: doc.ScanID}, Results: results,
		Invocations: []sarifInvocation{invocation},
		Properties:  map[string]string{"securityScannerSchemaVersion": doc.SchemaVersion, "securityScannerCoverage": coverageState},
	}}}
}

func sarifRuleID(finding Finding) string {
	if len(finding.CWEIDs) > 0 {
		return finding.CWEIDs[0]
	}
	return "SECURITY"
}

func buildSARIFRule(ruleID string, findings []Finding) sarifRule {
	name := sarifLabel(ruleID)
	cwes := make(map[string]struct{})
	remediations := make(map[string]struct{})
	tags := map[string]struct{}{"security": {}}
	maxSeverity := SeverityInfo
	for _, finding := range findings {
		if severityRank(finding.Severity) > severityRank(maxSeverity) {
			maxSeverity = finding.Severity
		}
		for _, cwe := range finding.CWEIDs {
			cwes[cwe] = struct{}{}
			upper := strings.ToUpper(cwe)
			if strings.HasPrefix(upper, "CWE-") {
				if number, err := strconv.Atoi(strings.TrimPrefix(upper, "CWE-")); err == nil && number > 0 {
					tags[fmt.Sprintf("external/cwe/cwe-%03d", number)] = struct{}{}
				}
			}
		}
		if remediation := strings.TrimSpace(finding.Remediation); remediation != "" {
			remediations[remediation] = struct{}{}
		}
	}
	orderedCWEs := sortedSet(cwes)
	description := name + "."
	if len(orderedCWEs) > 0 {
		description += " Weaknesses: " + strings.Join(orderedCWEs, ", ") + "."
	}
	remediation := strings.Join(sortedSet(remediations), "\n\n")
	helpText := description
	if remediation != "" {
		helpText += "\n\nRemediation:\n\n" + remediation
	}
	properties := map[string]any{"tags": sortedSet(tags)}
	if score := sarifSecurityScore(maxSeverity); score > 0 {
		properties["security-severity"] = strconv.FormatFloat(score, 'f', 1, 64)
	}
	return sarifRule{
		ID: ruleID, Name: name, ShortDescription: sarifMessage{Text: name}, FullDescription: sarifMessage{Text: description},
		Help:       sarifMultiformatMessage{Text: helpText, Markdown: strings.Replace(helpText, "\n\nRemediation:\n\n", "\n\n## Remediation\n\n", 1)},
		Properties: properties,
	}
}

func sarifLabel(value string) string {
	acronyms := map[string]struct{}{"api": {}, "csrf": {}, "html": {}, "http": {}, "id": {}, "rce": {}, "sql": {}, "ssrf": {}, "url": {}, "xml": {}, "xss": {}}
	words := strings.FieldsFunc(value, func(r rune) bool { return r == '-' || r == '_' || r == '.' || r == '/' })
	for index, word := range words {
		if _, ok := acronyms[strings.ToLower(word)]; ok {
			words[index] = strings.ToUpper(word)
		}
	}
	label := strings.Join(words, " ")
	if label == "" {
		return value
	}
	return strings.ToUpper(label[:1]) + label[1:]
}

func sarifFindingMessage(finding Finding) string {
	parts := []string{finding.Title, finding.Summary, "Severity: " + string(finding.Severity)}
	if len(finding.CWEIDs) > 0 {
		parts = append(parts, "Weaknesses: "+strings.Join(finding.CWEIDs, ", "))
	}
	parts = append(parts, "Remediation:\n"+finding.Remediation)
	return strings.Join(parts, "\n\n")
}

func sarifLocations(finding Finding) []sarifLocation {
	ordered := make([]Location, 0, len(finding.Locations))
	for _, location := range finding.Locations {
		if location.Role == "root_control" {
			ordered = append(ordered, location)
		}
	}
	for _, location := range finding.Locations {
		if location.Role != "root_control" {
			ordered = append(ordered, location)
		}
	}
	locations := make([]sarifLocation, 0, len(ordered))
	seen := make(map[string]struct{}, len(ordered))
	for _, location := range ordered {
		key := fmt.Sprintf("%s\x00%d\x00%d", location.Path, location.StartLine, location.EndLine)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		role := (*sarifMessage)(nil)
		if location.Role != "" {
			role = &sarifMessage{Text: location.Role}
		}
		locations = append(locations, sarifLocation{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: (&url.URL{Path: location.Path}).EscapedPath()},
			Region:           sarifRegion{StartLine: location.StartLine, EndLine: location.EndLine},
		}, Message: role})
	}
	return locations
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sarifSecurityScore(severity Severity) float64 {
	return map[Severity]float64{
		SeverityCritical: 9.5, SeverityHigh: 8.0, SeverityMedium: 5.0, SeverityLow: 2.0, SeverityInfo: 0.0,
	}[severity]
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
