package publication

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"security-scanner/internal/history"
	"security-scanner/internal/scan"
)

type Destination struct {
	Type      string `json:"type"`
	TeamID    string `json:"team_id"`
	ProjectID string `json:"project_id,omitempty"`
}

type PreparedIssue struct {
	FindingID    string `json:"finding_id"`
	OccurrenceID string `json:"occurrence_id"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Priority     int    `json:"priority,omitempty"`
}

type Prepared struct {
	ScanID        string          `json:"scan_id"`
	UploadID      string          `json:"upload_id"`
	ScanDirectory string          `json:"scan_directory"`
	Destination   Destination     `json:"destination"`
	Issues        []PreparedIssue `json:"issues"`
}

func Prepare(record history.Record, result *scan.Result, teamID, projectID string, uploadedAt time.Time) (Prepared, error) {
	teamID = strings.TrimSpace(teamID)
	projectID = strings.TrimSpace(projectID)
	if teamID == "" {
		return Prepared{}, fmt.Errorf("a Linear team is required for publication")
	}
	if result == nil {
		return Prepared{}, fmt.Errorf("a completed scan result is required")
	}
	manifest := result.Manifest
	if manifest.Status != "completed" && manifest.Status != "completed_with_gaps" {
		return Prepared{}, fmt.Errorf("scan %s is not completed and cannot be published", manifest.ScanID)
	}
	if manifest.SchemaVersion != scan.SchemaVersion || result.Findings.SchemaVersion != scan.SchemaVersion || result.Coverage.SchemaVersion != scan.SchemaVersion {
		return Prepared{}, fmt.Errorf("scan %s uses an unsupported artifact schema", manifest.ScanID)
	}
	if len(manifest.ArtifactDigests) == 0 {
		return Prepared{}, fmt.Errorf("scan %s is not sealed with canonical artifact digests", manifest.ScanID)
	}
	if strings.TrimSpace(manifest.ScanID) == "" || manifest.ScanID != record.ScanID || result.Findings.ScanID != manifest.ScanID || result.Coverage.ScanID != manifest.ScanID {
		return Prepared{}, fmt.Errorf("saved scan history and canonical artifact IDs do not match")
	}
	if manifest.FindingCount != len(result.Findings.Findings) {
		return Prepared{}, fmt.Errorf("scan %s finding count does not match its canonical findings", manifest.ScanID)
	}
	if !samePath(record.OutputDir, result.OutDir) {
		return Prepared{}, fmt.Errorf("selected scan directory differs from saved scan history")
	}
	if uploadedAt.IsZero() {
		uploadedAt = time.Now().UTC()
	}
	destination := Destination{Type: "linear", TeamID: teamID, ProjectID: projectID}
	prepared := Prepared{
		ScanID: manifest.ScanID, UploadID: manifest.ScanID, ScanDirectory: result.OutDir,
		Destination: destination, Issues: make([]PreparedIssue, 0, len(result.Findings.Findings)),
	}
	seen := make(map[string]struct{}, len(result.Findings.Findings))
	for _, finding := range result.Findings.Findings {
		if strings.TrimSpace(finding.ID) == "" || strings.TrimSpace(finding.Fingerprint) == "" || strings.TrimSpace(finding.Title) == "" {
			return Prepared{}, fmt.Errorf("scan %s contains an invalid canonical finding", manifest.ScanID)
		}
		if _, exists := seen[finding.ID]; exists {
			return Prepared{}, fmt.Errorf("scan %s contains duplicate finding ID %s", manifest.ScanID, finding.ID)
		}
		seen[finding.ID] = struct{}{}
		priority, err := linearPriority(finding.Severity)
		if err != nil {
			return Prepared{}, fmt.Errorf("finding %s: %w", finding.ID, err)
		}
		prepared.Issues = append(prepared.Issues, PreparedIssue{
			FindingID: finding.ID, OccurrenceID: manifest.ScanID + ":" + finding.ID,
			Title:       fmt.Sprintf("[Codex Security][%s] %s", strings.ToUpper(string(finding.Severity)), finding.Title),
			Description: renderDescription(result, finding, uploadedAt.UTC()), Priority: priority,
		})
	}
	return prepared, nil
}

func linearPriority(severity scan.Severity) (int, error) {
	switch severity {
	case scan.SeverityCritical:
		return 1, nil
	case scan.SeverityHigh:
		return 2, nil
	case scan.SeverityMedium:
		return 3, nil
	case scan.SeverityLow:
		return 4, nil
	case scan.SeverityInfo:
		return 0, nil
	default:
		return 0, fmt.Errorf("invalid severity %q", severity)
	}
}

func renderDescription(result *scan.Result, finding scan.Finding, uploadedAt time.Time) string {
	manifest := result.Manifest
	lines := []string{
		"## Codex Security finding", "",
		"**Scan ID:** " + manifest.ScanID,
		"**Finding ID:** " + finding.ID,
		"**Occurrence ID:** " + manifest.ScanID + ":" + finding.ID,
		"**Fingerprint:** " + finding.Fingerprint,
		"**Severity:** " + strings.ToUpper(string(finding.Severity)),
		"**Confidence:** " + strings.ToUpper(string(finding.Confidence)),
	}
	if len(finding.CWEIDs) > 0 {
		lines = append(lines, "**CWE:** "+strings.Join(finding.CWEIDs, ", "))
	}
	lines = append(lines,
		"", "## Scanned code", "",
		"**Repository:** "+repositoryDisplayName(manifest.Target),
	)
	if manifest.TargetRef != "" {
		lines = append(lines, "**Revision or base:** "+manifest.TargetRef)
	}
	scope := "entire repository"
	if len(manifest.TargetPaths) > 0 {
		scope = strings.Join(manifest.TargetPaths, ", ")
	}
	coverage := "complete"
	if result.Coverage.Summary.Unreviewed > 0 {
		coverage = "incomplete"
	}
	mode := manifest.TargetMode
	if mode == "" {
		mode = "repository"
	}
	lines = append(lines,
		"**Scanned scope:** "+scope,
		"**Coverage:** "+coverage,
		"**Scan mode:** "+mode,
		"**Started:** "+manifest.StartedAt.UTC().Format(time.RFC3339),
		"**Completed:** "+manifest.CompletedAt.UTC().Format(time.RFC3339),
		"**Uploaded:** "+uploadedAt.Format(time.RFC3339),
		"", "### Affected locations", "",
	)
	for _, location := range finding.Locations {
		lines = append(lines, fmt.Sprintf("- **%s:** `%s`", humanizeRole(location.Role), locationLabel(location)))
	}
	lines = append(lines, "", "## Summary", "", finding.Summary)
	if strings.TrimSpace(finding.Impact) != "" {
		lines = append(lines, "", "## Impact", "", finding.Impact)
	}
	if strings.TrimSpace(finding.AttackPath) != "" {
		lines = append(lines, "", "## Attack path", "", finding.AttackPath)
	}
	if strings.TrimSpace(finding.Evidence) != "" {
		lines = append(lines, "", "## Root cause and evidence", "", finding.Evidence)
	}
	withSnippets := false
	for _, location := range finding.Locations {
		if strings.TrimSpace(location.Snippet) == "" {
			continue
		}
		if !withSnippets {
			lines = append(lines, "", "## Source-code evidence")
			withSnippets = true
		}
		lines = append(lines, "", "### "+humanizeRole(location.Role), "", "**Location:** `"+locationLabel(location)+"`", "", fencedCode(location.Snippet))
	}
	lines = append(lines, "", "## Remediation", "", finding.Remediation)
	return strings.Join(lines, "\n") + "\n"
}

func locationLabel(location scan.Location) string {
	label := fmt.Sprintf("%s:%d", location.Path, location.StartLine)
	if location.EndLine > 0 && location.EndLine != location.StartLine {
		label += fmt.Sprintf("-%d", location.EndLine)
	}
	return label
}

func humanizeRole(role string) string {
	words := strings.ReplaceAll(strings.TrimSpace(role), "_", " ")
	if words == "" {
		return "Location"
	}
	return strings.ToUpper(words[:1]) + words[1:]
}

func fencedCode(code string) string {
	fence := "```"
	for strings.Contains(code, fence) {
		fence += "`"
	}
	return fence + "\n" + code + "\n" + fence
}

func samePath(left, right string) bool {
	rel, err := filepath.Rel(filepath.Clean(left), filepath.Clean(right))
	return err == nil && rel == "."
}

func repositoryDisplayName(target string) string {
	cleaned := filepath.Clean(target)
	name := filepath.Base(cleaned)
	if name == "" || name == "." || name == string(filepath.Separator) {
		return cleaned
	}
	return name
}
