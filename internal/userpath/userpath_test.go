package userpath

import (
	"path/filepath"
	"runtime"
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
