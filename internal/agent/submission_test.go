package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"

	"security-scanner/internal/scan"
)

func TestSubmissionToolValidatesBeforeStoring(t *testing.T) {
	inv := &scan.Inventory{Root: t.TempDir(), Files: []scan.File{{Path: "app.go", Lines: 3, Reviewable: true}}}
	store := NewSubmissionStore(inv)
	base, err := store.Tool()
	if err != nil {
		t.Fatal(err)
	}
	info, err := base.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "submit_scan" {
		t.Fatalf("tool name = %q", info.Name)
	}
	invokable, ok := base.(tool.InvokableTool)
	if !ok {
		t.Fatalf("submission tool is %T, want InvokableTool", base)
	}
	invalid, err := invokable.InvokableRun(context.Background(), `{"threat_model":""}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(invalid, `"accepted":false`) {
		t.Fatalf("invalid response = %s", invalid)
	}
	if _, ok := store.Get(); ok {
		t.Fatal("invalid submission was stored")
	}
	valid, err := invokable.InvokableRun(context.Background(), `{"threat_model":"Untrusted callers reach the service.","findings":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(valid, `"accepted":true`) {
		t.Fatalf("valid response = %s", valid)
	}
	if _, ok := store.Get(); !ok {
		t.Fatal("valid submission was not stored")
	}
}
