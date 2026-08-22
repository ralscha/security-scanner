package userpath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExpandHomeSupportsBothSeparators(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	for _, input := range []string{"~/reports/scan", `~\reports\scan`} {
		got, err := ExpandHome(input)
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(home, "reports", "scan")
		if got != want {
			t.Fatalf("ExpandHome(%q) = %q, want %q", input, got, want)
		}
	}
	if got, err := ExpandHome("relative/path"); err != nil || got != "relative/path" {
		t.Fatalf("ordinary path changed: %q, %v", got, err)
	}
}

func TestExpandHomeLeavesOtherUsersLiteral(t *testing.T) {
	got, err := ExpandHome("~someone/report")
	if err != nil || got != "~someone/report" {
		t.Fatalf("other-user path changed: %q, %v", got, err)
	}
}

func TestWindowsUnsafeComponent(t *testing.T) {
	for _, path := range []string{
		`reports\NUL.txt`, `reports\trailing.`, `reports\trailing `,
		`reports\has:stream`, `reports\COM¹.log`, "reports/control\x1f.json",
	} {
		if WindowsUnsafeComponent(path) == "" {
			t.Errorf("unsafe Windows path was accepted: %q", path)
		}
	}
	for _, path := range []string{`reports\scan`, `reports\console.txt`, `reports\com10.log`, `.`} {
		if component := WindowsUnsafeComponent(path); component != "" {
			t.Errorf("safe Windows path %q rejected at %q", path, component)
		}
	}
}

func TestResolveIfExistsCanonicalizesAliases(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}
	resolved, err := ResolveIfExists(alias)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(resolved, want) {
		t.Fatalf("resolved alias = %q, want %q", resolved, want)
	}
}
