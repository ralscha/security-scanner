package scan

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var cwePattern = regexp.MustCompile(`^CWE-[1-9][0-9]*$`)

func ValidateSubmission(inv *Inventory, submission Submission) []string {
	var problems []string
	if strings.TrimSpace(submission.ThreatModel) == "" {
		problems = append(problems, "threat_model is required")
	}
	if len(submission.Findings) > 200 {
		problems = append(problems, "findings exceeds maximum of 200")
	}
	files := make(map[string]File, len(inv.Files))
	for _, file := range inv.Files {
		files[file.Path] = file
	}
	for i := range submission.Findings {
		finding := &submission.Findings[i]
		prefix := fmt.Sprintf("findings[%d]", i)
		if strings.TrimSpace(finding.Title) == "" || strings.TrimSpace(finding.Summary) == "" || strings.TrimSpace(finding.Evidence) == "" {
			problems = append(problems, prefix+": title, summary, and evidence are required")
		}
		if strings.TrimSpace(finding.Impact) == "" || strings.TrimSpace(finding.Remediation) == "" || strings.TrimSpace(finding.AttackPath) == "" {
			problems = append(problems, prefix+": impact, remediation, and attack_path are required")
		}
		if !validSeverity(finding.Severity) {
			problems = append(problems, prefix+": invalid severity")
		}
		if !validConfidence(finding.Confidence) {
			problems = append(problems, prefix+": invalid confidence")
		}
		for _, cwe := range finding.CWEIDs {
			if !cwePattern.MatchString(cwe) {
				problems = append(problems, prefix+": invalid CWE id "+cwe)
			}
		}
		if len(finding.Locations) == 0 {
			problems = append(problems, prefix+": at least one location is required")
		}
		for j := range finding.Locations {
			loc := &finding.Locations[j]
			loc.Path = strings.Trim(strings.ReplaceAll(loc.Path, "\\", "/"), "/")
			file, ok := files[loc.Path]
			if !ok {
				problems = append(problems, fmt.Sprintf("%s.locations[%d]: path is not inventoried: %s", prefix, j, loc.Path))
				continue
			}
			if !file.Reviewable {
				problems = append(problems, fmt.Sprintf("%s.locations[%d]: path is not reviewable: %s", prefix, j, loc.Path))
			}
			if loc.StartLine < 1 || loc.StartLine > file.Lines {
				problems = append(problems, fmt.Sprintf("%s.locations[%d]: start_line is outside %s", prefix, j, loc.Path))
			}
			if loc.EndLine == 0 {
				loc.EndLine = loc.StartLine
			}
			if loc.EndLine < loc.StartLine || loc.EndLine > file.Lines {
				problems = append(problems, fmt.Sprintf("%s.locations[%d]: invalid end_line", prefix, j))
			}
			if strings.TrimSpace(loc.Role) == "" {
				problems = append(problems, fmt.Sprintf("%s.locations[%d]: role is required", prefix, j))
			}
		}
	}
	return problems
}

func NormalizeFindings(inv *Inventory, drafts []FindingDraft) ([]Finding, error) {
	files := make(map[string]File, len(inv.Files))
	for _, file := range inv.Files {
		files[file.Path] = file
	}
	findings := make([]Finding, 0, len(drafts))
	seen := make(map[string]struct{})
	for _, draft := range drafts {
		for i := range draft.Locations {
			loc := &draft.Locations[i]
			loc.Path = strings.Trim(strings.ReplaceAll(loc.Path, "\\", "/"), "/")
			if loc.EndLine == 0 {
				loc.EndLine = loc.StartLine
			}
			if loc.Snippet == "" {
				loc.Snippet = sourceSnippet(inv.Root, loc.Path, loc.StartLine, loc.EndLine)
			}
			if _, ok := files[loc.Path]; !ok {
				return nil, fmt.Errorf("finding location disappeared from inventory: %s", loc.Path)
			}
		}
		sort.Slice(draft.Locations, func(i, j int) bool {
			if draft.Locations[i].Path == draft.Locations[j].Path {
				return draft.Locations[i].StartLine < draft.Locations[j].StartLine
			}
			return draft.Locations[i].Path < draft.Locations[j].Path
		})
		sort.Strings(draft.CWEIDs)
		fingerprint := findingFingerprint(draft)
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		findings = append(findings, Finding{ID: "F-" + strings.ToUpper(fingerprint[:10]), Fingerprint: fingerprint, FindingDraft: draft})
	}
	sort.Slice(findings, func(i, j int) bool {
		left, right := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if left == right {
			return findings[i].ID < findings[j].ID
		}
		return left > right
	})
	return findings, nil
}

func findingFingerprint(f FindingDraft) string {
	var parts []string
	parts = append(parts, strings.ToLower(strings.TrimSpace(f.Title)))
	parts = append(parts, f.CWEIDs...)
	for _, loc := range f.Locations {
		parts = append(parts, fmt.Sprintf("%s:%s", loc.Path, strings.ToLower(strings.TrimSpace(loc.Role))))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return fmt.Sprintf("%x", sum[:])
}

func validSeverity(value Severity) bool {
	return value == SeverityCritical || value == SeverityHigh || value == SeverityMedium || value == SeverityLow || value == SeverityInfo
}

func validConfidence(value Confidence) bool {
	return value == ConfidenceHigh || value == ConfidenceMedium || value == ConfidenceLow
}

func severityRank(value Severity) int {
	return map[Severity]int{SeverityCritical: 5, SeverityHigh: 4, SeverityMedium: 3, SeverityLow: 2, SeverityInfo: 1}[value]
}
