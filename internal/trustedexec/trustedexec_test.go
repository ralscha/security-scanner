package trustedexec

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveSkipsProtectedPathEntries(t *testing.T) {
	protectedRoot := t.TempDir()
	protectedBin := filepath.Join(protectedRoot, "bin")
	externalBin := t.TempDir()
	for _, directory := range []string{protectedBin, externalBin} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, executableName("git")), []byte("test executable"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", strings.Join([]string{protectedBin, externalBin}, string(os.PathListSeparator)))

	resolved, err := Resolve("git", protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(externalBin, executableName("git")))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Path != want || !filepath.IsAbs(resolved.Path) {
		t.Fatalf("resolved path = %q, want %q", resolved.Path, want)
	}
	pathValue := environmentValue(resolved.Env, "PATH")
	if strings.Contains(strings.ToLower(pathValue), strings.ToLower(protectedBin)) || !strings.Contains(strings.ToLower(pathValue), strings.ToLower(externalBin)) {
		t.Fatalf("sanitized PATH = %q", pathValue)
	}
}

func TestResolveRejectsRelativePathEntries(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.Mkdir("bin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("bin", executableName("git")), []byte("test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "bin")
	if _, err := Resolve("git", root); err == nil {
		t.Fatal("relative PATH entry was trusted")
	}
}

func executableName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func environmentValue(environment []string, name string) string {
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok && strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}
