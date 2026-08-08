package bulk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	outputpolicy "security-scanner/internal/output"
)

func TestPendingReceiptUsesOmitZero(t *testing.T) {
	data, err := json.Marshal(JobReceipt{Job: Job{ID: "repo-1", Target: "repo"}, Status: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	for _, omitted := range []string{"started_at", "completed_at", "outcome"} {
		if strings.Contains(string(data), omitted) {
			t.Fatalf("zero field %q was not omitted: %s", omitted, data)
		}
	}
}

func TestParseInputDeduplicatesJSONTargets(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	path := filepath.Join(t.TempDir(), "repos.json")
	data := `[` + quote(first) + `,` + quote(second) + `,` + quote(first) + `]`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	jobs, err := ParseInput(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("unexpected jobs: %#v", jobs)
	}
}

func TestParseInputRejectsEmptyTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repos.json")
	if err := os.WriteFile(path, []byte(`[{"target":""}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInput(path); err == nil {
		t.Fatal("expected empty repository to be rejected")
	}
}

func TestParseAndPrepareJobsPreservesContext(t *testing.T) {
	root := t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "repos.json")
	data := `[{"target":` + quote(root) + `,"context":"internet-facing"}]`
	if err := os.WriteFile(inputPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInput(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := PrepareJobs(parsed, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Context != "internet-facing" || !filepath.IsAbs(jobs[0].OutputDir) {
		t.Fatalf("unexpected jobs: %#v", jobs)
	}
}

func TestCaseSensitiveRepositoryPathsRemainDistinct(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows paths are case-insensitive")
	}
	parent := t.TempDir()
	upper := filepath.Join(parent, "Repo")
	lower := filepath.Join(parent, "repo")
	if err := os.Mkdir(upper, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lower, 0o750); err != nil {
		t.Fatal(err)
	}
	jobs, err := normalizeJobs([]Job{{Target: upper}, {Target: lower}})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || jobs[0].ID == jobs[1].ID {
		t.Fatalf("case-sensitive repositories collapsed: %#v", jobs)
	}
}

func TestRunBoundsConcurrencyRetriesAndResumes(t *testing.T) {
	jobs, err := BuildJobs([]string{t.TempDir(), t.TempDir(), t.TempDir()}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var active, maximum, calls atomic.Int32
	runner := func(_ context.Context, job Job) (string, error) {
		call := calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		if call == 1 {
			return "", errors.New("provider returned 503 temporarily unavailable")
		}
		return "scan-" + job.ID, nil
	}
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	receipt, err := Run(context.Background(), jobs, runner, Config{Workers: 2, MaxRetries: 1, RetryDelay: time.Millisecond, ReceiptPath: receiptPath})
	if err != nil {
		t.Fatal(err)
	}
	if maximum.Load() > 2 || len(receipt.Jobs) != 3 {
		t.Fatalf("unexpected concurrency/receipt: %d %#v", maximum.Load(), receipt)
	}
	before := calls.Load()
	if _, err := Run(context.Background(), jobs, runner, Config{Workers: 2, Resume: true, ReceiptPath: receiptPath}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before {
		t.Fatal("completed receipt entries were rerun")
	}
}

func TestRunTreatsCompletedWithGapsAsSealedAcrossResume(t *testing.T) {
	jobs, err := BuildJobs([]string{t.TempDir()}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	runner := OutcomeRunner(func(_ context.Context, job Job) (Outcome, error) {
		calls.Add(1)
		return Outcome{
			ScanID: "scan-with-gaps", OutputDir: job.OutputDir,
			Status: StatusCompletedWithGaps, FindingCount: 2,
		}, nil
	})
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	receipt, err := Run(context.Background(), jobs, runner, Config{
		Workers: 1, MaxRetries: 3, RetryDelay: time.Millisecond, ReceiptPath: receiptPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || receipt.Status != StatusCompletedWithGaps || receipt.Jobs[0].Status != StatusCompletedWithGaps {
		t.Fatalf("incomplete result was not sealed: calls=%d receipt=%#v", calls.Load(), receipt)
	}
	if receipt.Jobs[0].Outcome.FindingCount != 2 {
		t.Fatalf("outcome metadata was not preserved: %#v", receipt.Jobs[0].Outcome)
	}
	if _, err := Run(context.Background(), jobs, runner, Config{
		Workers: 1, Resume: true, ReceiptPath: receiptPath,
	}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("sealed incomplete result was rerun during resume")
	}
}

func TestRunMigratesLegacyIncompleteReceiptWhenArtifactsAreSealed(t *testing.T) {
	jobs, err := BuildJobs([]string{t.TempDir()}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	job := jobs[0]
	guard, err := outputpolicy.PreparePrivateDir(job.OutputDir)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := map[string]string{
		"findings": "findings.json", "coverage": "coverage.json",
		"report": "report.md", "sarif": "results.sarif",
	}
	manifest, err := json.Marshal(map[string]any{
		"scan_id": "scan-legacy", "status": StatusCompletedWithGaps, "artifacts": artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"scan-manifest.json": manifest,
		"coverage.json":      []byte(`{"summary":{"unreviewed":1}}`),
		"findings.json":      []byte(`{"findings":[]}`),
		"report.md":          []byte("# Incomplete scan\n"),
		"results.sarif":      []byte(`{}`),
	}
	for name, data := range files {
		if err := outputpolicy.WritePrivateFileAtomic(guard, name, data); err != nil {
			t.Fatal(err)
		}
	}
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	legacy := Receipt{
		SchemaVersion: "1", Status: "incomplete", StartedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		Jobs: []JobReceipt{{
			Job: job, Status: "failed", ScanID: "scan-legacy", Attempts: 1,
			Error: "incomplete coverage: 1 unreviewed files", Cost: 1,
		}},
	}
	if err := saveReceipt(receiptPath, legacy); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	receipt, err := Run(context.Background(), jobs, OutcomeRunner(func(context.Context, Job) (Outcome, error) {
		calls.Add(1)
		return Outcome{}, errors.New("legacy sealed scan should not run")
	}), Config{Workers: 1, Resume: true, ReceiptPath: receiptPath})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || receipt.Status != StatusCompletedWithGaps || receipt.Jobs[0].Status != StatusCompletedWithGaps {
		t.Fatalf("legacy incomplete result was not recovered: calls=%d receipt=%#v", calls.Load(), receipt)
	}
}

func TestRunBudgetGuardrailAndNonTransientFailure(t *testing.T) {
	jobs, err := BuildJobs([]string{t.TempDir(), t.TempDir()}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	receipt, err := Run(context.Background(), jobs, func(context.Context, Job) (string, error) {
		calls.Add(1)
		return "", errors.New("invalid repository input")
	}, Config{
		Workers: 1, MaxRetries: 3, MaxBudget: 1, EstimatedCost: 1, ReceiptPath: filepath.Join(t.TempDir(), "receipt.json"),
	})
	if err == nil {
		t.Fatal("expected incomplete bulk result")
	}
	if calls.Load() != 1 || receipt.Jobs[0].Attempts != 1 || receipt.Jobs[1].Status != "budget_exceeded" {
		t.Fatalf("unexpected guardrail/retry behavior: calls=%d receipt=%#v", calls.Load(), receipt)
	}
}

func TestRunRedactsErrorsBeforeEventsAndReceiptPersistence(t *testing.T) {
	jobs, err := BuildJobs([]string{t.TempDir()}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	var events []Event
	receipt, err := Run(context.Background(), jobs, func(context.Context, Job) (string, error) {
		return "", errors.New("provider rejected authorization: Bearer super-secret-value")
	}, Config{
		Workers: 1, ReceiptPath: receiptPath,
		OnEvent: func(event Event) { events = append(events, event) },
	})
	if err == nil {
		t.Fatal("expected incomplete bulk result")
	}
	if len(receipt.Jobs) != 1 || strings.Contains(receipt.Jobs[0].Error, "super-secret-value") || !strings.Contains(receipt.Jobs[0].Error, "[redacted]") {
		t.Fatalf("receipt was not redacted: %#v", receipt.Jobs)
	}
	for _, event := range events {
		if strings.Contains(event.Message, "super-secret-value") {
			t.Fatalf("event leaked credential: %#v", event)
		}
	}
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("super-secret-value")) || !bytes.Contains(data, []byte("[redacted]")) {
		t.Fatalf("persisted receipt was not redacted: %s", data)
	}
}

func quote(value string) string {
	var result strings.Builder
	result.WriteString(`"`)
	for _, char := range value {
		if char == '\\' || char == '"' {
			result.WriteString(`\`)
		}
		result.WriteString(string(char))
	}
	return result.String() + `"`
}
