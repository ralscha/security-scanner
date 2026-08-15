package remediation

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveInputRejectsNonRegularFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := ResolveInput(root, root); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory error = %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks commonly requires elevated Windows privileges")
	}
	target := filepath.Join(root, "findings.json")
	link := filepath.Join(root, "linked-findings.json")
	if err := os.WriteFile(target, []byte(`{"schema_version":"1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveInput(link, root); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink error = %v", err)
	}
}
