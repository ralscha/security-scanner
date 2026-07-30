package match

import (
	"testing"

	"security-scanner/internal/scan"
)

func TestCompareClassifiesFindings(t *testing.T) {
	persistingBefore := finding("old-id", "stable", "SQL injection", "CWE-89", "db.go")
	persistingAfter := finding("new-id", "stable", "SQL injection", "CWE-89", "db.go")
	resolved := finding("resolved", "gone", "Old issue", "CWE-20", "old.go")
	added := finding("added", "new", "New issue", "CWE-79", "new.go")
	result := Compare(
		scan.FindingsDocument{ScanID: "before", Findings: []scan.Finding{persistingBefore, resolved}},
		scan.FindingsDocument{ScanID: "after", Findings: []scan.Finding{persistingAfter, added}},
	)
	if len(result.Persisting) != 1 || len(result.New) != 1 || len(result.Resolved) != 1 || len(result.Unknown) != 0 {
		t.Fatalf("unexpected comparison: %#v", result)
	}
}

func TestCompareUsesLocationAwareFallback(t *testing.T) {
	before := finding("before", "old-fingerprint", "Command injection", "CWE-78", "run.go")
	after := finding("after", "new-fingerprint", "Command injection vulnerability", "CWE-78", "run.go")
	result := Compare(scan.FindingsDocument{Findings: []scan.Finding{before}}, scan.FindingsDocument{Findings: []scan.Finding{after}})
	if len(result.Persisting) != 1 || result.Persisting[0].Confidence != "medium" {
		t.Fatalf("fallback did not match: %#v", result)
	}
}

func TestMarkReopenedUsesOlderHistory(t *testing.T) {
	returning := finding("returning", "known", "Old issue", "CWE-20", "old.go")
	comparison := MarkReopened(Comparison{New: []scan.Finding{returning}}, []scan.FindingsDocument{{Findings: []scan.Finding{returning}}})
	if len(comparison.New) != 0 || len(comparison.Reopened) != 1 {
		t.Fatalf("unexpected reopened classification: %#v", comparison)
	}
}

func TestCompareDoesNotMatchCaseDistinctPaths(t *testing.T) {
	before := scan.FindingsDocument{ScanID: "before", Findings: []scan.Finding{{FindingDraft: scan.FindingDraft{Title: "Issue", CWEIDs: []string{"CWE-20"}, Locations: []scan.Location{{Path: "Foo.go"}}}}}}
	after := scan.FindingsDocument{ScanID: "after", Findings: []scan.Finding{{FindingDraft: scan.FindingDraft{Title: "Issue", CWEIDs: []string{"CWE-20"}, Locations: []scan.Location{{Path: "foo.go"}}}}}}
	comparison := Compare(before, after)
	if len(comparison.Persisting) != 0 || len(comparison.New) != 1 || len(comparison.Resolved) != 1 {
		t.Fatalf("case-distinct paths matched: %#v", comparison)
	}
}

func finding(id, fingerprint, title, cwe, path string) scan.Finding {
	return scan.Finding{ID: id, Fingerprint: fingerprint, FindingDraft: scan.FindingDraft{
		Title: title, CWEIDs: []string{cwe}, Locations: []scan.Location{{Path: path, Role: "sink"}},
	}}
}
