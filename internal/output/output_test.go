package output

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidateDefersTargetBoundaryPolicy(t *testing.T) {
	root := t.TempDir()
	if _, err := Validate(context.Background(), root, filepath.Join(root, "reports"), false); err != nil {
		t.Fatalf("validate output inside target: %v", err)
	}
}

func TestValidateBoundaryRequiresDisjointPaths(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "repository")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, destination := range map[string]string{
		"inside":   filepath.Join(target, "reports"),
		"ancestor": parent,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateBoundary(context.Background(), target, destination); err == nil || !strings.Contains(err.Error(), "disjoint") {
				t.Fatalf("boundary error = %v", err)
			}
		})
	}
	if err := ValidateBoundary(context.Background(), target, filepath.Join(t.TempDir(), "reports")); err != nil {
		t.Fatalf("disjoint output rejected: %v", err)
	}
}

func TestValidateBoundaryProtectsEnclosingWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	worktree := t.TempDir()
	command := exec.Command("git", "-C", worktree, "init")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	target := filepath.Join(worktree, "service")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	err := ValidateBoundary(context.Background(), target, filepath.Join(worktree, "reports"))
	if err == nil || !strings.Contains(err.Error(), "disjoint") {
		t.Fatalf("enclosing worktree boundary error = %v", err)
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

func TestStateDirExpandsConfiguredHome(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	t.Setenv("SECURITY_SCANNER_STATE_DIR", `~\scanner-state`)
	got, err := StateDir()
	if err != nil {
		t.Fatal(err)
	}
	want, err := ResolvePath(filepath.Join(home, "scanner-state"))
	if err != nil {
		t.Fatal(err)
	}
	if !sameCanonicalPath(got, want) {
		t.Fatalf("state directory = %q, want %q", got, want)
	}
}

func TestResolvePathRejectsWindowsAmbiguousComponent(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific path semantics")
	}
	path := filepath.Join(t.TempDir(), "NUL.txt", "report")
	if _, err := ResolvePath(path); err == nil || !strings.Contains(err.Error(), "Windows-ambiguous") {
		t.Fatalf("ambiguous Windows path error = %v", err)
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
