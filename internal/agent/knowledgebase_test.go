package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"security-scanner/internal/knowledgebase"
)

func TestKnowledgeBaseToolsUseLogicalIDsAndTrackSeparately(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "guide.md")
	if err := os.WriteFile(path, []byte("first\nsecurity rule\nthird\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepared, err := knowledgebase.Prepare([]string{path}, knowledgebase.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tracker := NewKnowledgeAccessTracker()
	kb := NewKnowledgeBase(prepared, tracker)
	listed, err := kb.list(context.Background(), listKnowledgeArgs{})
	if err != nil || !strings.Contains(listed, prepared.Documents[0].ID) || strings.Contains(listed, path) {
		t.Fatalf("unexpected list result %q, %v", listed, err)
	}
	read, err := kb.read(context.Background(), readKnowledgeArgs{ID: prepared.Documents[0].ID})
	if err != nil || !strings.Contains(read, "UNTRUSTED KNOWLEDGE") || !strings.Contains(read, "security rule") {
		t.Fatalf("unexpected read result %q, %v", read, err)
	}
	searched, err := kb.search(context.Background(), searchKnowledgeArgs{Pattern: "security"})
	if err != nil || !strings.Contains(searched, `"line":2`) {
		t.Fatalf("unexpected search result %q, %v", searched, err)
	}
	if tracker.Snapshot()[prepared.Documents[0].ID] != 2 {
		t.Fatalf("knowledge access was not tracked independently: %#v", tracker.Snapshot())
	}
	if _, err := kb.read(context.Background(), readKnowledgeArgs{ID: path}); err == nil {
		t.Fatal("arbitrary filesystem path was accepted as a document ID")
	}
}

func TestKnowledgeBaseReadRejectsDrift(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "guide.txt")
	if err := os.WriteFile(path, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepared, err := knowledgebase.Prepare([]string{path}, knowledgebase.Options{})
	if err != nil {
		t.Fatal(err)
	}
	kb := NewKnowledgeBase(prepared, NewKnowledgeAccessTracker())
	if err := os.WriteFile(path, []byte("after\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := kb.read(context.Background(), readKnowledgeArgs{ID: prepared.Documents[0].ID}); err == nil {
		t.Fatal("drifted knowledge-base document was read")
	}
}
