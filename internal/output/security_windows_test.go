//go:build windows

package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPreparePrivateDirInstallsAndRevalidatesWindowsACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	guard, err := PreparePrivateDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Validate(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, "artifact.json")
	if err := os.WriteFile(file, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SecurePrivateFile(file); err != nil {
		t.Fatal(err)
	}
}
