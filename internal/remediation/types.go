package remediation

import (
	"fmt"
	"strings"

	"security-scanner/internal/scan"
)

type Validation struct {
	Verdict               string          `json:"verdict" jsonschema:"enum=true_positive,enum=false_positive,enum=needs_more_evidence"`
	Rationale             string          `json:"rationale"`
	Evidence              []scan.Location `json:"evidence"`
	ContradictingEvidence []scan.Location `json:"contradicting_evidence,omitempty"`
	RecommendedAction     string          `json:"recommended_action"`
}

type Change struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	Description string `json:"description"`
	Replacement string `json:"replacement"`
}

type PatchProposal struct {
	Summary      string   `json:"summary"`
	Rationale    string   `json:"rationale"`
	Changes      []Change `json:"changes"`
	Risks        []string `json:"risks,omitempty"`
	Verification []string `json:"verification"`
}

func ValidateValidation(inventory *scan.Inventory, result Validation) []string {
	var problems []string
	if result.Verdict != "true_positive" && result.Verdict != "false_positive" && result.Verdict != "needs_more_evidence" {
		problems = append(problems, "verdict is invalid")
	}
	if strings.TrimSpace(result.Rationale) == "" {
		problems = append(problems, "rationale is required")
	}
	if strings.TrimSpace(result.RecommendedAction) == "" {
		problems = append(problems, "recommended_action is required")
	}
	if result.Verdict != "needs_more_evidence" && len(result.Evidence) == 0 {
		problems = append(problems, "evidence is required for a conclusive verdict")
	}
	problems = append(problems, validateLocations(inventory, result.Evidence, "evidence")...)
	problems = append(problems, validateLocations(inventory, result.ContradictingEvidence, "contradicting_evidence")...)
	return problems
}

func ValidatePatch(inventory *scan.Inventory, proposal PatchProposal) []string {
	var problems []string
	if strings.TrimSpace(proposal.Summary) == "" || strings.TrimSpace(proposal.Rationale) == "" {
		problems = append(problems, "summary and rationale are required")
	}
	if len(proposal.Changes) == 0 {
		problems = append(problems, "at least one proposed change is required")
	}
	if len(proposal.Verification) == 0 {
		problems = append(problems, "at least one verification step is required")
	}
	files := fileMap(inventory)
	for i, change := range proposal.Changes {
		prefix := fmt.Sprintf("changes[%d]", i)
		path := normalizePath(change.Path)
		file, ok := files[path]
		if !ok || !file.Reviewable {
			problems = append(problems, prefix+": path is not a reviewable inventoried file")
			continue
		}
		if change.StartLine < 1 || change.EndLine < change.StartLine || change.EndLine > max(1, file.Lines) {
			problems = append(problems, prefix+": line range is invalid")
		}
		if strings.TrimSpace(change.Description) == "" || strings.TrimSpace(change.Replacement) == "" {
			problems = append(problems, prefix+": description and replacement are required")
		}
	}
	return problems
}

func validateLocations(inventory *scan.Inventory, locations []scan.Location, field string) []string {
	files := fileMap(inventory)
	var problems []string
	for i, location := range locations {
		file, ok := files[normalizePath(location.Path)]
		if !ok || !file.Reviewable {
			problems = append(problems, fmt.Sprintf("%s[%d]: path is not a reviewable inventoried file", field, i))
			continue
		}
		end := location.EndLine
		if end == 0 {
			end = location.StartLine
		}
		if location.StartLine < 1 || end < location.StartLine || end > file.Lines {
			problems = append(problems, fmt.Sprintf("%s[%d]: line range is invalid", field, i))
		}
	}
	return problems
}

func fileMap(inventory *scan.Inventory) map[string]scan.File {
	files := make(map[string]scan.File, len(inventory.Files))
	for _, file := range inventory.Files {
		files[file.Path] = file
	}
	return files
}

func normalizePath(value string) string {
	return strings.Trim(strings.ReplaceAll(value, "\\", "/"), "/")
}
