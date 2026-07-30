package policy

import (
	"fmt"
	"strings"

	"security-scanner/internal/scan"
)

type Evaluation struct {
	Threshold scan.Severity `json:"threshold,omitempty"`
	Violated  bool          `json:"violated"`
	Matches   []string      `json:"matching_findings,omitempty"`
}

func ParseSeverity(value string) (scan.Severity, error) {
	severity := scan.Severity(strings.ToLower(strings.TrimSpace(value)))
	if severity == "" {
		return "", nil
	}
	if rank(severity) == 0 {
		return "", fmt.Errorf("invalid severity %q; expected critical, high, medium, low, or info", value)
	}
	return severity, nil
}

func Evaluate(findings []scan.Finding, threshold scan.Severity) Evaluation {
	evaluation := Evaluation{Threshold: threshold}
	if threshold == "" {
		return evaluation
	}
	for _, finding := range findings {
		if rank(finding.Severity) >= rank(threshold) {
			evaluation.Matches = append(evaluation.Matches, finding.ID)
		}
	}
	evaluation.Violated = len(evaluation.Matches) > 0
	return evaluation
}

func rank(value scan.Severity) int {
	switch value {
	case scan.SeverityCritical:
		return 5
	case scan.SeverityHigh:
		return 4
	case scan.SeverityMedium:
		return 3
	case scan.SeverityLow:
		return 2
	case scan.SeverityInfo:
		return 1
	default:
		return 0
	}
}
