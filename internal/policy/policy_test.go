package policy

import (
	"reflect"
	"testing"

	"security-scanner/internal/scan"
)

func TestEvaluateSeverityThreshold(t *testing.T) {
	findings := []scan.Finding{
		{ID: "critical", FindingDraft: scan.FindingDraft{Severity: scan.SeverityCritical}},
		{ID: "medium", FindingDraft: scan.FindingDraft{Severity: scan.SeverityMedium}},
		{ID: "low", FindingDraft: scan.FindingDraft{Severity: scan.SeverityLow}},
	}
	evaluation := Evaluate(findings, scan.SeverityMedium)
	if !evaluation.Violated || !reflect.DeepEqual(evaluation.Matches, []string{"critical", "medium"}) {
		t.Fatalf("unexpected evaluation: %#v", evaluation)
	}
}

func TestParseSeverityRejectsUnknownValue(t *testing.T) {
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Fatal("expected invalid severity error")
	}
}
