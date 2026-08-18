package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"

	"security-scanner/internal/scan"
)

func TestModelToolResultRedactsCredentials(t *testing.T) {
	result, err := modelToolResult("read_file", "", errors.New("api_key=super-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result, "super-secret-value") || !strings.Contains(result, "[redacted]") {
		t.Fatalf("credential escaped into model tool result: %s", result)
	}
}

func TestRepositoryReadTrackingAndSearch(t *testing.T) {
	root := t.TempDir()
	var content strings.Builder
	for i := 1; i <= 450; i++ {
		if i == 225 {
			content.WriteString("dangerousExecute(userInput)\n")
		} else {
			content.WriteString("safe line\n")
		}
	}
	path := filepath.Join(root, "app.go")
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := scan.BuildInventory(root, scan.InventoryOptions{MaxFileBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	tracker := NewReadTracker()
	repo := NewRepository(inv, tracker)
	file := inv.Files[0]

	search, err := repo.searchCode(context.Background(), searchCodeArgs{Pattern: "dangerousExecute"})
	if err != nil || !strings.Contains(search, `"line":225`) {
		t.Fatalf("search = %q, err = %v", search, err)
	}
	if tracker.Complete(file) {
		t.Fatal("search must not count as full review")
	}
	first, err := repo.readFile(context.Background(), readFileArgs{Path: "app.go", StartLine: 1})
	if err != nil || !strings.Contains(first, "NEXT start_line=401") {
		t.Fatalf("first read did not paginate: %v\n%s", err, first)
	}
	if tracker.Complete(file) {
		t.Fatal("partial read counted as complete")
	}
	if _, err := repo.readFile(context.Background(), readFileArgs{Path: "app.go", StartLine: 401}); err != nil {
		t.Fatal(err)
	}
	if !tracker.Complete(file) {
		t.Fatal("complete consecutive reads were not tracked")
	}
	if _, err := repo.readFile(context.Background(), readFileArgs{Path: "../app.go"}); err == nil {
		t.Fatal("path traversal should be rejected")
	}
}

func TestArchitectureReadsDoNotContributeToAuditCoverage(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := scan.BuildInventory(root, scan.InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	auditTracker := NewReadTracker()
	_, architecture := newScanRepositories(inv, auditTracker)
	if _, err := architecture.readFile(context.Background(), readFileArgs{Path: "app.go"}); err != nil {
		t.Fatal(err)
	}
	if auditTracker.Complete(inv.Files[0]) {
		t.Fatal("architecture-only read counted as completed security-audit coverage")
	}
}

func TestRepositoryRejectsContentChangedAfterInventory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "app.go")
	if err := os.WriteFile(path, []byte("package old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := scan.BuildInventory(root, scan.InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewRepository(inv, NewReadTracker()).readFile(context.Background(), readFileArgs{Path: "app.go"})
	if err == nil || !strings.Contains(err.Error(), "changed after inventory") {
		t.Fatalf("stale repository read was not rejected: %v", err)
	}
}

func TestRepositoryToolReturnsInvalidRangeToModel(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("first\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := scan.BuildInventory(root, scan.InventoryOptions{MaxFileBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	repositoryTools, err := NewRepository(inv, NewReadTracker()).Tools()
	if err != nil {
		t.Fatal(err)
	}

	var readTool tool.InvokableTool
	for _, candidate := range repositoryTools {
		info, infoErr := candidate.Info(context.Background())
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		if info.Name == "read_file" {
			readTool = candidate.(tool.InvokableTool)
			break
		}
	}
	if readTool == nil {
		t.Fatal("read_file tool not found")
	}

	result, err := readTool.InvokableRun(context.Background(), `{"path":"app.go","start_line":2,"end_line":1}`)
	if err != nil {
		t.Fatalf("model-correctable argument error escaped tool: %v", err)
	}
	if !strings.Contains(result, `"ok":false`) || !strings.Contains(result, "end_line must be at least start_line") {
		t.Fatalf("unexpected tool result: %s", result)
	}
}

func TestRepositoryProvidesSearchFileCompatibilityAlias(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("dangerousExecute(input)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := scan.BuildInventory(root, scan.InventoryOptions{MaxFileBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	repositoryTools, err := NewRepository(inv, NewReadTracker()).Tools()
	if err != nil {
		t.Fatal(err)
	}

	var searchFile tool.InvokableTool
	for _, candidate := range repositoryTools {
		info, infoErr := candidate.Info(context.Background())
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		if info.Name == "search_file" {
			searchFile = candidate.(tool.InvokableTool)
			break
		}
	}
	if searchFile == nil {
		t.Fatal("search_file compatibility tool not found")
	}
	result, err := searchFile.InvokableRun(context.Background(), `{"pattern":"dangerousExecute"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, `"path":"app.go"`) || !strings.Contains(result, `"line":1`) {
		t.Fatalf("unexpected search_file result: %s", result)
	}
}
