package postscan

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"security-scanner/internal/output"
	"security-scanner/internal/scan"
)

func TestWriteArtifactsDoesNotChangeCanonicalFiles(t *testing.T) {
	guard, err := output.PreparePrivateDir(filepath.Join(t.TempDir(), "scan"))
	if err != nil {
		t.Fatal(err)
	}
	canonical := []string{"findings.json", "coverage.json", "report.md", "results.sarif"}
	want := make(map[string][32]byte)
	for _, name := range canonical {
		data := []byte("canonical " + name + "\n")
		if err := output.WritePrivateFileAtomic(guard, name, data); err != nil {
			t.Fatal(err)
		}
		want[name] = sha256.Sum256(data)
	}
	scanID := scan.AllocateScanID(t.TempDir(), time.Unix(300, 0))
	if err := WriteArtifacts(guard, Result{
		SchemaVersion: SchemaVersion, ScanID: scanID, Trigger: "success", Summary: "Review complete.",
		Actions:   []Action{{Title: "Harden deployment", Rationale: "Reduce exposure."}},
		StartedAt: time.Unix(300, 0), CompletedAt: time.Unix(301, 0),
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range canonical {
		data, err := os.ReadFile(filepath.Join(guard.Path(), name))
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(data); got != want[name] {
			t.Fatalf("canonical artifact %s changed", name)
		}
	}
	for _, name := range []string{"post-scan.json", "post-scan.md"} {
		if _, err := os.Stat(filepath.Join(guard.Path(), name)); err != nil {
			t.Fatal(err)
		}
	}
}
