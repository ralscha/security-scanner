//go:build linux || darwin

package output

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsAccessibleExistingOutput(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "report")
	if err := os.Mkdir(out, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(context.Background(), root, out, false); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("privacy validation error = %v", err)
	}
}

func TestValidateRejectsWritableNonStickyAncestor(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(context.Background(), root, filepath.Join(shared, "report"), false); err == nil || !strings.Contains(err.Error(), "sticky bit") {
		t.Fatalf("ancestry validation error = %v", err)
	}
}
