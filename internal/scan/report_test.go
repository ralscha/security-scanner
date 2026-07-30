package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type completeTracker map[string]bool

func (t completeTracker) Complete(file File) bool { return t[file.Path] }

func TestFinalizeWritesContractAndSARIF(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "app.go", []byte("package app\nfunc run() {}\n"))
	writeTestFile(t, root, "logo.bin", []byte{1, 0, 2})
	inv, err := BuildInventory(root, InventoryOptions{MaxFileBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report")
	result, err := Finalize(inv, completeTracker{"app.go": true}, Submission{
		ThreatModel: "Untrusted callers can invoke the application.",
		Findings: []FindingDraft{{
			Title: "Example issue", Severity: SeverityMedium, Confidence: ConfidenceHigh, CWEIDs: []string{"CWE-20"},
			Summary: "Input is not validated.", Impact: "Unexpected behavior", Evidence: "run lacks validation",
			Remediation: "Validate input.", AttackPath: "Caller invokes run.",
			Locations: []Location{{Path: "app.go", StartLine: 2, Role: "root_control"}},
		}},
	}, FinalizeOptions{OutputDir: out, Provider: "test-provider", Model: "test-model", StartedAt: time.Unix(100, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Status != "completed" || result.Manifest.FindingCount != 1 {
		t.Fatalf("unexpected manifest: %#v", result.Manifest)
	}
	for _, name := range []string{"findings.json", "coverage.json", "report.md", "results.sarif", "scan-manifest.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("artifact %s: %v", name, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(out, "results.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	var sarif map[string]any
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatal(err)
	}
	if sarif["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %#v", sarif["version"])
	}
}

func TestFinalizeMarksIncompleteCoverage(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "unread.go", []byte("package unread\n"))
	inv, err := BuildInventory(root, InventoryOptions{MaxFileBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Finalize(inv, completeTracker{}, Submission{ThreatModel: "No exposed entrypoints found."}, FinalizeOptions{
		OutputDir: filepath.Join(t.TempDir(), "report"), Provider: "test-provider", Model: "test", StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Status != "completed_with_gaps" || result.Coverage.Summary.Unreviewed != 1 {
		t.Fatalf("incomplete coverage was not surfaced: %#v", result)
	}
}
