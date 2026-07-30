package targeting

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

	diff, err := Resolve(context.Background(), root, Selector{DiffRef: base})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(diff.Paths, []string{"tracked.go"}) {
		t.Fatalf("diff paths = %#v", diff.Paths)
	}
	working, err := Resolve(context.Background(), root, Selector{WorkingTree: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(working.Paths, []string{"new.go", "tracked.go"}) {
		t.Fatalf("working paths = %#v", working.Paths)
	}
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
