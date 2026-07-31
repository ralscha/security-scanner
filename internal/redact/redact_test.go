package redact

import (
	"bytes"
	"strings"
	"testing"
)

func TestTextRedactsCredentialShapes(t *testing.T) {
	tests := []string{
		`api_key=super-secret-value request failed`,
		`{"apiKey":"super-secret-value","model":"x"}`,
		`payload={\"accessToken\":\"super-secret-value\"}`,
		`Authorization: Custom super-secret-value`,
		`request used Bearer super-secret-value`,
		`https://user:super-secret-value@example.test/v1`,
		`https://example.test/v1?token=super-secret-value&mode=test`,
		`provider returned sk-proj-abcdefghijklmnopqrstuvwxyz`,
		"private_key=-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			redacted := Text(input)
			if strings.Contains(redacted, "super-secret-value") || strings.Contains(redacted, "abcdefghijklmnopqrstuvwxyz") || strings.Contains(redacted, "\nsecret\n") {
				t.Fatalf("credential survived redaction: %q", redacted)
			}
			if !strings.Contains(redacted, "[redacted") {
				t.Fatalf("redaction marker missing: %q", redacted)
			}
		})
	}
}

func TestTextKeepsNonCredentialErrorsReadable(t *testing.T) {
	input := "permission denied while writing report.md"
	if got := Text(input); got != input {
		t.Fatalf("message changed: %q", got)
	}
}

func TestWriterRedactsAndPreservesInputLength(t *testing.T) {
	var destination bytes.Buffer
	input := []byte("provider failed: token=super-secret-value\n")
	written, err := Writer(&destination).Write(input)
	if err != nil || written != len(input) {
		t.Fatalf("write = %d, %v", written, err)
	}
	if strings.Contains(destination.String(), "super-secret-value") || !strings.Contains(destination.String(), "[redacted]") {
		t.Fatalf("unexpected destination: %q", destination.String())
	}
}
