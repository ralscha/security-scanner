package knowledgebase

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrepareContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := PrepareContext(ctx, []string{t.TempDir()}, Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestPrepareDiscoversNormalizesDeduplicatesAndVerifies(t *testing.T) {
	root := t.TempDir()
	writeKBFile(t, root, "z.txt", []byte("z\r\nline\r\n"))
	writeKBFile(t, root, "nested/a.md", []byte("alpha\n"))
	writeKBFile(t, root, "ignored.json", []byte(`{"ignored":true}`))

	prepared, err := Prepare([]string{root, filepath.Join(root, "nested", "a.md")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Documents) != 2 || prepared.Documents[0].Name != "a.md" || prepared.Documents[1].Name != "z.txt" {
		t.Fatalf("unexpected deterministic inventory: %#v", prepared.Documents)
	}
	if prepared.Documents[1].Text != "z\nline\n" {
		t.Fatalf("CRLF was not normalized: %q", prepared.Documents[1].Text)
	}
	if prepared.Digest == "" {
		t.Fatal("aggregate digest is empty")
	}
	if err := Verify(prepared); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "z.txt"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(prepared); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed document was not rejected: %v", err)
	}
}

func TestPrepareRejectsUnsupportedInvalidAndBoundedInputs(t *testing.T) {
	root := t.TempDir()
	unsupported := filepath.Join(root, "file.json")
	if err := os.WriteFile(unsupported, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare([]string{unsupported}, Options{}); err == nil {
		t.Fatal("explicit unsupported file was accepted")
	}
	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare([]string{empty}, Options{}); err == nil {
		t.Fatal("directory without supported documents was accepted")
	}
	invalid := filepath.Join(root, "invalid.md")
	if err := os.WriteFile(invalid, []byte{0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare([]string{invalid}, Options{}); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 was not rejected: %v", err)
	}
	nul := filepath.Join(root, "contains-zero.txt")
	if err := os.WriteFile(nul, []byte{'a', 0, 'b'}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare([]string{nul}, Options{}); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("NUL was not rejected: %v", err)
	}
	large := filepath.Join(root, "large.txt")
	if err := os.WriteFile(large, []byte("too large"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare([]string{large}, Options{MaxDocumentBytes: 3}); err == nil {
		t.Fatal("per-document limit was not enforced")
	}
}

func TestPrepareEnforcesCountAndAggregateLimits(t *testing.T) {
	root := t.TempDir()
	writeKBFile(t, root, "a.md", []byte("1234"))
	writeKBFile(t, root, "b.md", []byte("5678"))
	if _, err := Prepare([]string{root}, Options{MaxDocuments: 1}); err == nil {
		t.Fatal("document-count limit was not enforced")
	}
	if _, err := Prepare([]string{root}, Options{MaxTotalBytes: 7}); err == nil {
		t.Fatal("aggregate limit was not enforced")
	}
}

func TestVerifyDetectsAddedRemovedAndReplacedDocuments(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.md")
	writeKBFile(t, root, "a.md", []byte("same\n"))
	prepared, err := Prepare([]string{root}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	writeKBFile(t, root, "b.md", []byte("added\n"))
	if err := Verify(prepared); err == nil {
		t.Fatal("added document was not detected")
	}
	if err := os.Remove(filepath.Join(root, "b.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := Verify(prepared); err == nil {
		t.Fatal("removed document was not detected")
	}
	writeKBFile(t, root, "a.md", []byte("same\n"))
	if err := Verify(prepared); err == nil {
		t.Fatal("same-content replacement was not detected")
	}
}

func TestPrepareRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks commonly requires elevated Windows privileges")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target.md")
	writeKBFile(t, root, "target.md", []byte("text"))
	link := filepath.Join(root, "link.md")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare([]string{link}, Options{}); err == nil {
		t.Fatal("symlink root was accepted")
	}
	if _, err := Prepare([]string{root}, Options{}); err == nil {
		t.Fatal("symlink inside directory was accepted")
	}
}

func TestPrepareExpandsCurrentUserHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	writeKBFile(t, home, "guide.md", []byte("guide"))
	prepared, err := Prepare([]string{"~/guide.md"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Documents) != 1 {
		t.Fatalf("documents = %d", len(prepared.Documents))
	}
	if _, err := Prepare([]string{"~someone/guide.md"}, Options{}); err == nil {
		t.Fatal("other-user home expansion was accepted")
	}
}

func writeKBFile(t *testing.T, root, name string, data []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
