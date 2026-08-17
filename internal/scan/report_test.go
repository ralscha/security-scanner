package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type completeTracker map[string]bool

func (t completeTracker) Complete(file File) bool { return t[file.Path] }

func TestFinalizeRequiresAllocatedScanID(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "app.go", []byte("package app\n"))
	inv, err := BuildInventory(root, InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Finalize(inv, nil, Submission{ThreatModel: "Untrusted callers."}, FinalizeOptions{OutputDir: filepath.Join(t.TempDir(), "out")}); err == nil || !strings.Contains(err.Error(), "scan ID") {
		t.Fatalf("missing scan ID was accepted: %v", err)
	}
}

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
	}, FinalizeOptions{ScanID: AllocateScanID(root, time.Unix(100, 0)), OutputDir: out, Provider: "test-provider", Model: "test-model", StartedAt: time.Unix(100, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Status != "completed" || result.Manifest.FindingCount != 1 {
		t.Fatalf("unexpected manifest: %#v", result.Manifest)
	}
	if len(result.Manifest.ArtifactDigests) != 4 || !strings.HasPrefix(result.Manifest.ArtifactDigests["findings.json"], "sha256:") || result.Manifest.ArtifactDigests["scan-log.jsonl"] != "" {
		t.Fatalf("canonical artifact digests missing: %#v", result.Manifest.ArtifactDigests)
	}
	for _, name := range []string{"findings.json", "coverage.json", "report.md", "results.sarif", "scan-log.jsonl", "scan-manifest.json"} {
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
		ScanID: AllocateScanID(root, time.Unix(200, 0)), OutputDir: filepath.Join(t.TempDir(), "report"), Provider: "test-provider", Model: "test", StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Status != "completed_with_gaps" || result.Coverage.Summary.Unreviewed != 1 {
		t.Fatalf("incomplete coverage was not surfaced: %#v", result)
	}
}

func TestFinalizeRetainsActivityLogForExplicitAPIKeyScan(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "app.go", []byte("package app\n"))
	inv, err := BuildInventory(root, InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report")
	result, err := Finalize(inv, nil, Submission{ThreatModel: "No exposed entrypoints found."}, FinalizeOptions{
		ScanID: AllocateScanID(root, time.Unix(100, 0)), OutputDir: out, Provider: "test-provider", Model: "test", StartedAt: time.Unix(100, 0),
		LaunchConfig: &LaunchConfiguration{AuthMode: "api-key", RequiresExplicitAPIKey: true},
		Activity:     []ActivityEvent{{Timestamp: time.Unix(101, 0), Event: "scan.started", Message: "scan started"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Artifacts["log"] != "scan-log.jsonl" {
		t.Fatalf("log artifact missing from manifest: %#v", result.Manifest.Artifacts)
	}
	data, err := os.ReadFile(filepath.Join(out, "scan-log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"event":"scan.started"`) || !strings.Contains(lines[1], `"event":"scan.completed"`) {
		t.Fatalf("unexpected scan log: %s", data)
	}
	if strings.Contains(string(data), "api-key") {
		t.Fatalf("authentication configuration leaked into scan log: %s", data)
	}
}

func TestFinalizeRejectsChangedTarget(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "app.go", []byte("package old\n"))
	inv, err := BuildInventory(root, InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, "app.go", []byte("package new\n"))
	out := filepath.Join(t.TempDir(), "report")
	_, err = Finalize(inv, completeTracker{"app.go": true}, Submission{ThreatModel: "Untrusted callers."}, FinalizeOptions{
		ScanID: AllocateScanID(root, time.Unix(300, 0)), OutputDir: out, Provider: "test-provider", Model: "test", StartedAt: time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "scan target changed") {
		t.Fatalf("stale target was not rejected: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(out, "scan-manifest.json")); !os.IsNotExist(statErr) {
		t.Fatalf("stale scan manifest was published: %v", statErr)
	}
}
