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

func TestResolveRejectsProtectedRelativePathEntries(t *testing.T) {
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

func TestResolveAcceptsSafeRelativePathEntries(t *testing.T) {
	root := t.TempDir()
	repository := filepath.Join(root, "repository")
	trustedBin := filepath.Join(root, "trusted")
	if err := os.Mkdir(repository, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(trustedBin, 0o755); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(trustedBin, executableName("git"))
	if err := os.WriteFile(executable, []byte("test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	t.Setenv("PATH", "trusted")
	resolved, err := Resolve("git", repository)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Path != want || !filepath.IsAbs(resolved.Path) {
		t.Fatalf("resolved path = %q, want %q", resolved.Path, want)
	}
}

func TestGitEnvironmentScopesConfiguration(t *testing.T) {
	environment := []string{
		"KEEP=ok", "GIT_DIR=unsafe", "git_shallow_file=unsafe", "GIT_ALLOW_PROTOCOL=ext",
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=secret",
	}
	preserved := GitEnvironment(environment, true)
	if environmentValue(preserved, "KEEP") != "ok" || environmentValue(preserved, "GIT_CONFIG_COUNT") != "1" {
		t.Fatalf("safe configuration was not preserved: %#v", preserved)
	}
	if environmentValue(preserved, "GIT_DIR") != "" || environmentValue(preserved, "GIT_SHALLOW_FILE") != "" || environmentValue(preserved, "GIT_ALLOW_PROTOCOL") != "" {
		t.Fatalf("repository or protocol override survived: %#v", preserved)
	}
	isolated := GitEnvironment(environment, false)
	if environmentValue(isolated, "KEEP") != "ok" || environmentValue(isolated, "GIT_CONFIG_COUNT") != "" || environmentValue(isolated, "GIT_CONFIG_VALUE_0") != "" {
		t.Fatalf("Git configuration was exposed: %#v", isolated)
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
