package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildInventoryAccountsForTextAndSkippedFiles(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "src/main.go", []byte("package main\n\nfunc main() {}\n"))
	writeTestFile(t, root, "empty.txt", nil)
	writeTestFile(t, root, "asset.bin", []byte{1, 0, 2})
	writeTestFile(t, root, "large.txt", []byte("123456789012345678901234567890123456789012345678901234567890"))
	writeTestFile(t, root, ".git/config", []byte("ignored"))
	writeTestFile(t, root, ".scanner/old/report.md", []byte("ignored"))

	inv, err := BuildInventory(root, InventoryOptions{MaxFileBytes: 50})
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(inv.Files))
	for _, file := range inv.Files {
		paths = append(paths, file.Path)
	}
	want := []string{"asset.bin", "empty.txt", "large.txt", "src/main.go"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
	byPath := filesByPath(inv.Files)
	if byPath["asset.bin"].SkipReason != "binary" {
		t.Fatalf("binary skip reason = %q", byPath["asset.bin"].SkipReason)
	}
	if byPath["large.txt"].SkipReason != "file_too_large" {
		t.Fatalf("large skip reason = %q", byPath["large.txt"].SkipReason)
	}
	if got := byPath["src/main.go"].Lines; got != 3 {
		t.Fatalf("line count = %d, want 3", got)
	}
	if !byPath["empty.txt"].Reviewable {
		t.Fatal("empty text file should be reviewable")
	}
}

func TestBuildInventoryIncludesSelectedPaths(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "cmd/main.go", []byte("package main\n"))
	writeTestFile(t, root, "internal/app.go", []byte("package internal\n"))
	writeTestFile(t, root, "README.md", []byte("docs\n"))

	inv, err := BuildInventory(root, InventoryOptions{Includes: []string{"cmd", "README.md"}})
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(inv.Files))
	for _, file := range inv.Files {
		paths = append(paths, file.Path)
	}
	if want := []string{"README.md", "cmd/main.go"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
}

func TestBuildInventoryHonorsNestedGitignoreRules(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, ".gitignore", []byte("*.log\ncache/\ngenerated/*\n!generated/keep.go\n"))
	writeTestFile(t, root, "app.go", []byte("package app\n"))
	writeTestFile(t, root, "debug.log", []byte("ignored\n"))
	writeTestFile(t, root, "cache/data.go", []byte("ignored\n"))
	writeTestFile(t, root, "generated/drop.go", []byte("ignored\n"))
	writeTestFile(t, root, "generated/keep.go", []byte("package generated\n"))
	writeTestFile(t, root, "src/.gitignore", []byte("*.tmp\n"))
	writeTestFile(t, root, "src/drop.tmp", []byte("ignored\n"))
	writeTestFile(t, root, "src/keep.go", []byte("package src\n"))
	writeTestFile(t, root, "other/keep.tmp", []byte("not ignored by nested rule\n"))

	inv, err := BuildInventory(root, InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(inv.Files))
	for _, file := range inv.Files {
		paths = append(paths, file.Path)
	}
	want := []string{".gitignore", "app.go", "generated/keep.go", "other/keep.tmp", "src/.gitignore", "src/keep.go"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
}

func TestBuildInventoryIncludesExplicitlySelectedIgnoredPaths(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, ".gitignore", []byte("secret.env\nignored.env\nsrc/ignored.env\nvendor/\n"))
	writeTestFile(t, root, "secret.env", []byte("ignored\n"))
	writeTestFile(t, root, "ignored.env", []byte("ignored\n"))
	writeTestFile(t, root, "src/app.go", []byte("package app\n"))
	writeTestFile(t, root, "src/ignored.env", []byte("ignored within broad selected scope\n"))
	writeTestFile(t, root, "vendor/dependency.go", []byte("package dependency\n"))
	writeTestFile(t, root, "vendor/private.env", []byte("ignored within selected dependency scope\n"))
	writeTestFile(t, root, ".git/config", []byte("protected metadata\n"))

	inv, err := BuildInventory(root, InventoryOptions{Includes: []string{".git", "secret.env", "src", "vendor"}})
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(inv.Files))
	for _, file := range inv.Files {
		paths = append(paths, file.Path)
	}
	want := []string{"secret.env", "src/app.go", "vendor/dependency.go", "vendor/private.env"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
}

func TestVerifyInventoryDetectsContentAndScopeChanges(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "app.go", []byte("package old\n"))
	inv, err := BuildInventory(root, InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInventory(inv); err != nil {
		t.Fatalf("unchanged inventory failed verification: %v", err)
	}
	writeTestFile(t, root, "app.go", []byte("package new\n"))
	if err := VerifyInventory(inv); err == nil || !strings.Contains(err.Error(), "scan target changed") {
		t.Fatalf("content drift was not detected: %v", err)
	}
	writeTestFile(t, root, "app.go", []byte("package old\n"))
	writeTestFile(t, root, "new.go", []byte("package added\n"))
	if err := VerifyInventory(inv); err == nil || !strings.Contains(err.Error(), "scan target changed") {
		t.Fatalf("scope drift was not detected: %v", err)
	}
}

func writeTestFile(t *testing.T, root, relative string, content []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func filesByPath(files []File) map[string]File {
	result := make(map[string]File, len(files))
	for _, file := range files {
		result[file.Path] = file
	}
	return result
}
