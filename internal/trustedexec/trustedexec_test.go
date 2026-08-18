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

func TestResolveDropsPathEntryWithProtectedExecutableAlias(t *testing.T) {
	protectedRoot := t.TempDir()
	aliasBin := t.TempDir()
	trustedBin := t.TempDir()
	name := executableName("git")
	protectedExecutable := filepath.Join(protectedRoot, name)
	if err := os.WriteFile(protectedExecutable, []byte("protected"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protectedExecutable, filepath.Join(aliasBin, name)); err != nil {
		t.Skipf("file symlinks are unavailable: %v", err)
	}
	trustedExecutable := filepath.Join(trustedBin, name)
	if err := os.WriteFile(trustedExecutable, []byte("trusted"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", strings.Join([]string{aliasBin, trustedBin}, string(os.PathListSeparator)))

	resolved, err := Resolve("git", protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(trustedExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Path != want {
		t.Fatalf("resolved path = %q, want %q", resolved.Path, want)
	}
	pathValue := environmentValue(resolved.Env, "PATH")
	if strings.Contains(strings.ToLower(pathValue), strings.ToLower(aliasBin)) ||
		!strings.Contains(strings.ToLower(pathValue), strings.ToLower(trustedBin)) {
		t.Fatalf("sanitized PATH = %q", pathValue)
	}
}

func TestExecutableSuffixesMatchWindowsCreateProcessRules(t *testing.T) {
	bare := executableSuffixes("git", false, true)
	if len(bare) != 5 || bare[0].value != ".exe" || !bare[0].runnable ||
		bare[1].value != ".com" || !bare[1].runnable ||
		bare[2].value != ".bat" || bare[2].runnable ||
		bare[3].value != ".cmd" || bare[3].runnable || bare[4].runnable {
		t.Fatalf("unexpected bare Windows candidates: %#v", bare)
	}
	explicit := executableSuffixes(filepath.Join("tools", "python"), true, true)
	if len(explicit) != 1 || explicit[0].value != ".exe" || !explicit[0].runnable {
		t.Fatalf("unexpected extensionless explicit Windows candidate: %#v", explicit)
	}
	batch := executableSuffixes(filepath.Join("tools", "python.cmd"), true, true)
	if len(batch) != 1 || batch[0].value != "" || batch[0].runnable {
		t.Fatalf("unexpected explicit batch candidate: %#v", batch)
	}
}

func TestSanitizedEnvironmentDropsUnsafePathEntries(t *testing.T) {
	first, second := filepath.Join("trusted", "first"), filepath.Join("trusted", "second")
	environment := sanitizedEnvironment([]string{first, second}, map[string]struct{}{first: {}})
	got := environmentValue(environment, "PATH")
	if strings.Contains(got, first) || !strings.Contains(got, second) {
		t.Fatalf("sanitized PATH = %q", got)
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
