package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"security-scanner/internal/scan"
)

func TestInventoryCommand(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"inventory", "--target", root}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var inv scan.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Files) != 1 || inv.Files[0].Path != "main.go" {
		t.Fatalf("unexpected inventory: %#v", inv)
	}
}

func TestInventoryFailureUsesRuntimeExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"inventory", "--target", filepath.Join(t.TempDir(), "missing")}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestOutputFailureUsesRuntimeExitCode(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"help"}, errorWriter{}, &stderr); code != 2 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != version {
		t.Fatalf("version = %q, want %q", got, version)
	}
}

func TestExitCodeForSignal(t *testing.T) {
	if got := exitCodeForSignal(os.Interrupt); got != 130 {
		t.Fatalf("interrupt exit = %d", got)
	}
	if got := exitCodeForSignal(syscall.SIGTERM); got != 143 {
		t.Fatalf("terminate exit = %d", got)
	}
}

func TestScanRequiresAPIKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("SECURITY_SCANNER_API_KEY", "")
	t.Setenv("SECURITY_SCANNER_PROVIDER", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--api-key=", "--target", t.TempDir()}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("API key is required for provider openai")) {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestScanDryRunDoesNotCallModel(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--dry-run", "--target", root, "--api-key", "not-used", "--path", "main.go"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	var payload struct {
		DryRun bool `json:"dry_run"`
		Scan   struct {
			Inventory scan.Inventory `json:"inventory"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.DryRun || len(payload.Scan.Inventory.Files) != 1 {
		t.Fatalf("unexpected dry-run payload: %s", stdout.String())
	}
}

func TestScanRejectsConflictingTargetSelectors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--target", t.TempDir(), "--path", ".", "--working-tree"}, &stdout, &stderr)
	if code != 2 || !bytes.Contains(stderr.Bytes(), []byte("mutually exclusive")) {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestProvidersCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"providers"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, provider := range []string{"openai", "azure-openai", "openai-compatible", "openrouter", "anthropic", "gemini", "ollama", "ark"} {
		if !bytes.Contains(stdout.Bytes(), []byte(provider)) {
			t.Errorf("provider output does not contain %q:\n%s", provider, stdout.String())
		}
	}
}

func TestHelpListsRoadmapCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, command := range []string{"scan preflight", "bulk-scan", "scans <list|show|rerun|match|compare>", "findings false-positive", "validate", "patch"} {
		if !strings.Contains(stdout.String(), command) {
			t.Errorf("help does not contain %q:\n%s", command, stdout.String())
		}
	}
}

func TestPreflightJSONDoesNotCallModel(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "preflight", "--target", root, "--provider", "ollama", "--model", "not-installed", "--auth", "none", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || !result.OK {
		t.Fatalf("unexpected preflight: %s, %v", stdout.String(), err)
	}
}

func TestPreflightJSONRedactsCredentialsInTargetErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "api_key=super-secret-value")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "preflight", "--target", missing, "--json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d: stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "super-secret-value") || !strings.Contains(stdout.String(), "[redacted]") {
		t.Fatalf("credential escaped into JSON preflight error: %s", stdout.String())
	}
}

func TestLifecycleAndBulkCommandsValidateArguments(t *testing.T) {
	for _, args := range [][]string{{"scans"}, {"bulk-scan"}, {"findings", "false-positive", "F-1"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("%v exit = %d, stderr = %s", args, code, stderr.String())
		}
	}
}

func TestFindingsFalsePositiveRequiresReason(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"findings", "false-positive", "scan-1:F-ABC"}, &stdout, &stderr)
	if code != 2 || !bytes.Contains(stderr.Bytes(), []byte("requires --reason")) {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestValidateRequiresInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"validate"}, &stdout, &stderr)
	if code != 2 || !bytes.Contains(stderr.Bytes(), []byte("FINDING_OR_PROMPT")) {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestWriteNewFileDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proposal.json")
	if err := writeNewFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFile(path, []byte("second")); err == nil {
		t.Fatal("expected existing export to be preserved")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first" {
		t.Fatalf("export was overwritten: %q", data)
	}
}
