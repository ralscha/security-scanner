package policy

import (
	"reflect"
	"testing"

	"security-scanner/internal/scan"
)

func TestEvaluateSeverityThreshold(t *testing.T) {
	findings := []scan.Finding{
		{ID: "critical", Severity: scan.SeverityCritical},
		{ID: "medium", Severity: scan.SeverityMedium},
		{ID: "low", Severity: scan.SeverityLow},
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
