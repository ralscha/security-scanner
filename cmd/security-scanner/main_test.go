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

	"security-scanner/internal/history"
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

func TestScanVerboseDiagnosticsStayOnStderr(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_LOG_LEVEL", "")
	t.Setenv("LOG_LEVEL", "")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan", "--dry-run", "--quiet", "--verbose", "--target", root,
		"--provider", "ollama", "--model", "test-model", "--auth", "none",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("verbose diagnostics corrupted stdout: %s", stdout.String())
	}
	for _, event := range []string{"scan.configuration", "scan.target_resolved", "scan.preflight.completed"} {
		if !strings.Contains(stderr.String(), "security-scanner: debug: "+event) {
			t.Errorf("missing %s diagnostic:\n%s", event, stderr.String())
		}
	}
}

func TestVerboseDiagnosticsCanBeEnabledByEnvironment(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_LOG_LEVEL", "debug")
	t.Setenv("LOG_LEVEL", "")
	var output bytes.Buffer
	writer := &checkedWriter{writer: &output}
	logger := newDiagnosticLogger(false, writer)
	logger.Log("scan.test", map[string]any{"ok": true})
	if !logger.Enabled() || !strings.Contains(output.String(), "security-scanner: debug: scan.test") {
		t.Fatalf("environment did not enable diagnostics: %q", output.String())
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
	for _, provider := range []string{"openai", "azure-openai", "openai-compatible", "openrouter", "fireworks", "anthropic", "gemini", "ollama", "ark"} {
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

func TestRerunScanArgsPreserveSavedConfiguration(t *testing.T) {
	record := history.Record{
		ScanID: "scan-1", Target: `C:\repo`, Provider: "fireworks", Model: "accounts/fireworks/models/test",
		TargetMode: "path", TargetPaths: []string{"cmd", "internal/auth"},
		LaunchConfig: &scan.LaunchConfiguration{
			AuthMode: "env", BaseURL: "https://example.test/v1", MaxOutputTokens: 4096,
			UserContext: "internet-facing", Excludes: []string{"vendor"}, MaxFileBytes: 2048,
			MaxIterations: 12, MaxAgentConcurrency: 3, RequestTimeout: "2m0s", MaxDuration: "15m0s",
			FailOnSeverity: "high",
		},
	}
	args, err := rerunScanArgs(record, true)
	if err != nil {
		t.Fatal(err)
	}
	for flag, value := range map[string]string{
		"--provider": "fireworks", "--auth": "env", "--base-url": "https://example.test/v1",
		"--max-output-tokens": "4096", "--context": "internet-facing", "--exclude": "vendor",
		"--max-file-bytes": "2048", "--max-iterations": "12", "--max-agent-concurrency": "3",
		"--request-timeout": "2m0s", "--max-duration": "15m0s", "--fail-on-severity": "high",
	} {
		if !containsFlagValue(args, flag, value) {
			t.Errorf("rerun args do not contain %s %q: %#v", flag, value, args)
		}
	}
	if !containsFlagValue(args, "--path", "cmd") || !containsFlagValue(args, "--path", "internal/auth") || !slicesContain(args, "--verbose") {
		t.Fatalf("rerun targeting or verbose setting was lost: %#v", args)
	}
}

func TestRerunScanArgsDoNotPersistExplicitAPIKey(t *testing.T) {
	_, err := rerunScanArgs(history.Record{
		Target: t.TempDir(), Provider: "openai", Model: "test",
		LaunchConfig: &scan.LaunchConfiguration{AuthMode: "auto", RequiresExplicitAPIKey: true},
	}, false)
	if err == nil || !strings.Contains(err.Error(), "API keys are not stored") {
		t.Fatalf("expected actionable API-key rerun error, got %v", err)
	}
}

func containsFlagValue(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func slicesContain(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
