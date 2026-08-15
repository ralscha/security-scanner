package safeinput

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prompt.txt")
	if err := os.WriteFile(path, []byte("review this\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadRegularFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "review this\n" {
		t.Fatalf("data = %q", data)
	}
}

func TestReadRegularFileRejectsNonRegularInputs(t *testing.T) {
	if _, err := ReadRegularFile(t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory error = %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks commonly requires elevated Windows privileges")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	if err := os.WriteFile(target, []byte("text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink error = %v", err)
	}
}
