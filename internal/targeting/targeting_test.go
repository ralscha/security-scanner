package targeting

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSelectorConflict(t *testing.T) {
	err := (Selector{Paths: []string{"cmd"}, DiffRef: "HEAD"}).Validate()
	if err == nil {
		t.Fatal("expected selector conflict")
	}
}

func TestResolvePathsRejectsOutsideTarget(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.go")
	if err := os.WriteFile(outside, []byte("package outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(context.Background(), root, Selector{Paths: []string{outside}}); err == nil {
		t.Fatal("expected outside path to be rejected")
	}
}

func TestResolveGitDiffAndWorkingTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	root := t.TempDir()
	runTestGit(t, root, "init")
	runTestGit(t, root, "config", "user.email", "scanner@example.invalid")
	runTestGit(t, root, "config", "user.name", "Scanner Test")
	writeTargetFile(t, root, "tracked.go", "package sample\n")
	runTestGit(t, root, "add", "tracked.go")
	runTestGit(t, root, "commit", "-m", "initial")
	base := runTestGit(t, root, "rev-parse", "HEAD")
	writeTargetFile(t, root, "tracked.go", "package sample\n// changed\n")
	writeTargetFile(t, root, "new.go", "package sample\n")
	runTestGit(t, root, "add", "tracked.go", "new.go")
	runTestGit(t, root, "commit", "-m", "change files")

	diff, err := Resolve(context.Background(), root, Selector{DiffRef: base})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(diff.Paths, []string{"new.go", "tracked.go"}) {
		t.Fatalf("diff paths = %#v", diff.Paths)
	}
	writeTargetFile(t, root, "tracked.go", "package sample\n// working tree\n")
	writeTargetFile(t, root, "untracked.go", "package sample\n")
	working, err := Resolve(context.Background(), root, Selector{WorkingTree: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(working.Paths, []string{"tracked.go", "untracked.go"}) {
		t.Fatalf("working paths = %#v", working.Paths)
	}
}

func TestResolveGitDiffRejectsDirtyCheckout(t *testing.T) {
	root, base := newTestGitRepository(t)
	writeTargetFile(t, root, "tracked.go", "package sample\n// dirty\n")

	_, err := Resolve(context.Background(), root, Selector{DiffRef: base})
	if err == nil || !strings.Contains(err.Error(), "clean repository checkout") {
		t.Fatalf("expected dirty checkout error, got %v", err)
	}
}

func TestResolveGitDiffRejectsSparseCheckout(t *testing.T) {
	root, base := newTestGitRepository(t)
	runTestGit(t, root, "update-index", "--skip-worktree", "tracked.go")

	_, err := Resolve(context.Background(), root, Selector{DiffRef: base})
	if err == nil || !strings.Contains(err.Error(), "sparse checkouts") {
		t.Fatalf("expected sparse checkout error, got %v", err)
	}
}

func TestResolveGitDiffTreatsRevisionAsData(t *testing.T) {
	root, _ := newTestGitRepository(t)
	unexpectedOutput := filepath.Join(t.TempDir(), "git-output")

	_, err := Resolve(context.Background(), root, Selector{DiffRef: "--output=" + unexpectedOutput})
	if err == nil {
		t.Fatal("expected invalid revision to be rejected")
	}
	if _, statErr := os.Stat(unexpectedOutput); !os.IsNotExist(statErr) {
		t.Fatalf("revision was interpreted as a Git option: %v", statErr)
	}
}

func TestResolveGitDiffIgnoresRepositoryEnvironmentOverrides(t *testing.T) {
	root, base := newTestGitRepository(t)
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "missing-git-dir"))
	t.Setenv("GIT_WORK_TREE", filepath.Join(t.TempDir(), "missing-work-tree"))
	t.Setenv("GIT_SHALLOW_FILE", filepath.Join(t.TempDir(), "missing-shallow-file"))
	if _, err := Resolve(context.Background(), root, Selector{DiffRef: base}); err != nil {
		t.Fatalf("repository override affected diff resolution: %v", err)
	}
}

func newTestGitRepository(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	root := t.TempDir()
	runTestGit(t, root, "init")
	runTestGit(t, root, "config", "user.email", "scanner@example.invalid")
	runTestGit(t, root, "config", "user.name", "Scanner Test")
	writeTargetFile(t, root, "tracked.go", "package sample\n")
	runTestGit(t, root, "add", "tracked.go")
	runTestGit(t, root, "commit", "-m", "initial")
	return root, runTestGit(t, root, "rev-parse", "HEAD")
}

func runTestGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return string(bytesTrimSpace(output))
}

func bytesTrimSpace(value []byte) []byte {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}

func writeTargetFile(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
