package preflight

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"security-scanner/internal/app"
)

func TestRunValidatesWithoutBuildingModel(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_SCANNER_STATE_DIR", t.TempDir())
	result := Run(context.Background(), app.Options{Target: root, Provider: "ollama", Model: "not-installed", AuthMode: "none"})
	if !result.OK || result.FilesTotal != 1 || result.Provider != "ollama" {
		t.Fatalf("unexpected preflight: %#v", result)
	}
}

func TestRunRedactsConfigurationErrors(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := Run(context.Background(), app.Options{
		Target: root, Provider: "token=super-secret-value", Model: "model", AuthMode: "none",
	})
	if result.OK || len(result.Checks) != 1 {
		t.Fatalf("unexpected preflight result: %#v", result)
	}
	message := result.Checks[0].Message
	if strings.Contains(message, "super-secret-value") || !strings.Contains(message, "[redacted]") {
		t.Fatalf("configuration error was not redacted: %q", message)
	}
}

func TestRunReportsConfigurationFailure(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("SECURITY_SCANNER_API_KEY", "")
	result := Run(context.Background(), app.Options{Target: t.TempDir(), Provider: "openai", Model: "model", AuthMode: "env"})
	if result.OK || len(result.Checks) != 1 || result.Checks[0].Status != "error" {
		t.Fatalf("unexpected preflight: %#v", result)
	}
}
