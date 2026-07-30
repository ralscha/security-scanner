package scan

import (
	"strings"
	"testing"
)

func TestValidateAndNormalizeSubmission(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "app.go", []byte("package app\nvar input string\nfunc run() { execute(input) }\n"))
	inv, err := BuildInventory(root, InventoryOptions{MaxFileBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	draft := FindingDraft{
		Title: "Command injection", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		CWEIDs: []string{"CWE-78"}, Summary: "Untrusted input reaches command execution.",
		Impact: "Arbitrary commands", Evidence: "input flows to execute", Remediation: "Use a fixed executable and argument vector.",
		AttackPath: "A caller controls input.",
		Locations:  []Location{{Path: "app.go", StartLine: 3, Role: "sink"}},
	}
	submission := Submission{ThreatModel: "Callers can provide input.", Findings: []FindingDraft{draft}}
	if problems := ValidateSubmission(inv, submission); len(problems) != 0 {
		t.Fatalf("unexpected validation problems: %v", problems)
	}
	first, err := NormalizeFindings(inv, []FindingDraft{draft, draft})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NormalizeFindings(inv, []FindingDraft{draft})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].ID != second[0].ID {
		t.Fatalf("normalization is not deterministic: %#v %#v", first, second)
	}
	if !strings.Contains(first[0].Locations[0].Snippet, "execute(input)") {
		t.Fatalf("missing source snippet: %q", first[0].Locations[0].Snippet)
	}
}

func TestValidateSubmissionRejectsUnknownEvidence(t *testing.T) {
	inv := &Inventory{Root: t.TempDir(), Files: []File{{Path: "known.go", Lines: 1, Reviewable: true}}}
	submission := Submission{
		ThreatModel: "A threat model",
		Findings: []FindingDraft{{
			Title: "Bad path", Severity: SeverityHigh, Confidence: ConfidenceHigh,
			Summary: "summary", Impact: "impact", Evidence: "evidence", Remediation: "fix", AttackPath: "path",
			Locations: []Location{{Path: "../secret", StartLine: 1, Role: "sink"}},
		}},
	}
	problems := ValidateSubmission(inv, submission)
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, " "), "not inventoried") {
		t.Fatalf("expected unknown path error, got %v", problems)
	}
}

func TestFindingFingerprintSurvivesLineMovement(t *testing.T) {
	base := FindingDraft{
		Title: "Command injection", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		CWEIDs: []string{"CWE-78"}, Locations: []Location{{Path: "cmd/run.go", StartLine: 10, EndLine: 12, Role: "sink"}},
	}
	moved := base
	moved.Locations = []Location{{Path: "cmd/run.go", StartLine: 40, EndLine: 42, Role: "sink"}}
	if findingFingerprint(base) != findingFingerprint(moved) {
		t.Fatal("line movement changed the semantic fingerprint")
	}
}

func TestFindingFingerprintPreservesPathCase(t *testing.T) {
	upper := findingFingerprint(FindingDraft{Title: "Issue", CWEIDs: []string{"CWE-20"}, Locations: []Location{{Path: "Foo.go", Role: "sink"}}})
	lower := findingFingerprint(FindingDraft{Title: "Issue", CWEIDs: []string{"CWE-20"}, Locations: []Location{{Path: "foo.go", Role: "sink"}}})
	if upper == lower {
		t.Fatal("case-distinct paths produced the same fingerprint")
	}
}
