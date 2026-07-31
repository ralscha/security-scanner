package output

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidateAllowsOutputInsideTarget(t *testing.T) {
	root := t.TempDir()
	if _, err := Validate(context.Background(), root, filepath.Join(root, "reports"), false); err != nil {
		t.Fatalf("validate output inside target: %v", err)
	}
}

func TestPrivateGuardWritesReadsAndRejectsReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private")
	guard, err := PreparePrivateDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFileAtomic(guard, "artifact.json", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	data, err := ReadPrivateFile(guard, "artifact.json")
	if err != nil || string(data) != "{}\n" {
		t.Fatalf("read = %q, %v", data, err)
	}
	archived := filepath.Join(root, "original")
	if err := os.Rename(path, archived); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.Validate(); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("replacement validation error = %v", err)
	}
}

func TestReadPrivateFileRejectsNonBaseName(t *testing.T) {
	guard, err := PreparePrivateDir(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(guard, filepath.Join("nested", "artifact.json")); err == nil {
		t.Fatal("expected nested private artifact name to be rejected")
	}
}

func TestDefaultScanDirPreservesCaseOnCaseSensitiveSystems(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows paths are case-insensitive")
	}
	t.Setenv("SECURITY_SCANNER_STATE_DIR", t.TempDir())
	now := time.Unix(1, 0)
	parent := t.TempDir()
	upper, err := DefaultScanDir(filepath.Join(parent, "Repo"), now)
	if err != nil {
		t.Fatal(err)
	}
	lower, err := DefaultScanDir(filepath.Join(parent, "repo"), now)
	if err != nil {
		t.Fatal(err)
	}
	if upper == lower {
		t.Fatal("case-distinct targets produced the same default output directory")
	}
}

func TestValidateRequiresArchiveForNonEmptyOutput(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(t.TempDir(), "report")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(context.Background(), root, out, false); err == nil {
		t.Fatal("expected non-empty output error")
	}
	if _, err := Validate(context.Background(), root, out, true); err != nil {
		t.Fatalf("archive-enabled validation failed: %v", err)
	}
}

func TestPrepareArchivesWithCollisionSafeName(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	first := out + ".archive-20260730T120000Z"
	if err := os.MkdirAll(first, 0o700); err != nil {
		t.Fatal(err)
	}
	archived, err := Prepare(out, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if archived != first+"-1" {
		t.Fatalf("archive = %q", archived)
	}
	if _, err := os.Stat(filepath.Join(archived, "old.txt")); err != nil {
		t.Fatal(err)
	}
}
