package app

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestRejectOutputSymlinksInsideTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks commonly requires elevated Windows privileges")
	}
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, ".scanner")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := rejectOutputSymlinks(root, filepath.Join(link, "scan")); err == nil {
		t.Fatal("expected symlinked output path to be rejected")
	}
}

func TestPrepareResolvesAndExcludesAbsoluteOutputInsideTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(root, "reports")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "stale.txt"), []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	prepared, err := Prepare(Options{
		Target:          root,
		OutputDir:       outputDir,
		Provider:        "ollama",
		Model:           "test-model",
		AuthMode:        "none",
		ArchiveExisting: true,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(prepared.OutputDir) || prepared.OutputDir != outputDir {
		t.Fatalf("output directory = %q, want absolute %q", prepared.OutputDir, outputDir)
	}
	for _, file := range prepared.Inventory.Files {
		if file.Path == "reports/stale.txt" {
			t.Fatal("output directory was included in the scan inventory")
		}
	}
}

func TestSamePath(t *testing.T) {
	root := t.TempDir()
	if !samePath(root, filepath.Join(root, ".")) {
		t.Fatal("equivalent paths should compare equal")
	}
}
