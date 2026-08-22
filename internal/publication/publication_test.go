package publication

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"security-scanner/internal/history"
	linearapi "security-scanner/internal/linear"
	"security-scanner/internal/scan"
)

func TestSamePathCanonicalizesAlias(t *testing.T) {
	real := filepath.Join(t.TempDir(), "scan")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "scan-alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}
	if !samePath(alias, real) {
		t.Fatalf("canonical alias %q did not match %q", alias, real)
	}
}

func TestPrepareRendersTraceableLinearIssuesAndPriorities(t *testing.T) {
	record, result := publicationFixture(t, 5)
	severities := []scan.Severity{scan.SeverityCritical, scan.SeverityHigh, scan.SeverityMedium, scan.SeverityLow, scan.SeverityInfo}
	for index := range result.Findings.Findings {
		result.Findings.Findings[index].Severity = severities[index]
	}
	prepared, err := Prepare(record, result, "team-1", "project-1", time.Date(2026, 8, 17, 10, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if prepared.ScanID != record.ScanID || prepared.UploadID != record.ScanID || prepared.Destination.ProjectID != "project-1" {
		t.Fatalf("prepared = %#v", prepared)
	}
	for index, priority := range []int{1, 2, 3, 4, 0} {
		issue := prepared.Issues[index]
		if issue.Priority != priority || !strings.HasPrefix(issue.Title, "[Codex Security]["+strings.ToUpper(string(severities[index]))+"]") {
			t.Fatalf("issue %d = %#v", index, issue)
		}
	}
	description := prepared.Issues[0].Description
	for _, expected := range []string{
		"**Scan ID:** scan-publication", "**Finding ID:** F-1", "**Occurrence ID:** scan-publication:F-1",
		"**Repository:** " + filepath.Base(result.Manifest.Target), "**Coverage:** incomplete", "**Scan mode:** working_tree",
		"**CWE:** CWE-79", "**Sink:** `src/main.go:10-12`", "## Impact", "## Attack path",
		"## Root cause and evidence", "## Source-code evidence", "````\nunsafe(```)\n````", "## Remediation",
	} {
		if !strings.Contains(description, expected) {
			t.Fatalf("description missing %q:\n%s", expected, description)
		}
	}
}

func TestPrepareRejectsUnsealedOrMismatchedArtifacts(t *testing.T) {
	record, result := publicationFixture(t, 1)
	result.Manifest.Status = "failed"
	if _, err := Prepare(record, result, "team", "", time.Now()); err == nil || !strings.Contains(err.Error(), "not completed") {
		t.Fatalf("status error = %v", err)
	}
	_, result = publicationFixture(t, 1)
	result.Findings.SchemaVersion = "2"
	if _, err := Prepare(record, result, "team", "", time.Now()); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("schema error = %v", err)
	}
}

func TestPublishUsesConcurrentBatchesPreservesFailuresAndWritesReceipt(t *testing.T) {
	record, scanResult := publicationFixture(t, 23)
	client := &fakeClient{totalFirstBatch: 20, failTitle: "Finding 22"}
	state := filepath.Join(t.TempDir(), "state")
	events := 0
	result, err := Publish(context.Background(), record, scanResult, Options{
		TeamID: "team", ProjectID: "project", Client: client, StateDir: state,
		Now:      func() time.Time { return time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC) },
		Progress: func(Progress) { events++; panic("observer must be nonfatal") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Counts != (Counts{Findings: 23, Created: 22, Failed: 1}) || len(result.Failed) != 1 || result.Failed[0].FindingID != "F-22" {
		t.Fatalf("result = %#v", result)
	}
	if client.maxInFlight != 20 || client.secondBatchStartedBeforeFirstFinished {
		t.Fatalf("batch behavior: max=%d early=%v", client.maxInFlight, client.secondBatchStartedBeforeFirstFinished)
	}
	if events == 0 {
		t.Fatal("expected progress calls")
	}
	if _, err := os.Stat(result.ReceiptPath); err != nil {
		t.Fatalf("receipt %q: %v", result.ReceiptPath, err)
	}
	handoffs := filepath.Join(state, "publications", "handoffs")
	entries, err := os.ReadDir(handoffs)
	if err != nil || len(entries) != 0 {
		t.Fatalf("completed handoffs = %v, %v", entries, err)
	}
}

func TestPublishDryRunDoesNotRequireCredentialsOrWriteState(t *testing.T) {
	record, scanResult := publicationFixture(t, 2)
	state := filepath.Join(t.TempDir(), "unused-state")
	result, err := Publish(context.Background(), record, scanResult, Options{TeamID: "team", DryRun: true, StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	if !result.DryRun || len(result.Issues) != 2 || result.Counts.Findings != 2 {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run wrote state: %v", err)
	}
}

func TestPublishResolvesEmailAssigneeAndSupportsTeamOnlyIssues(t *testing.T) {
	record, scanResult := publicationFixture(t, 1)
	client := &assignmentClient{}
	result, err := Publish(context.Background(), record, scanResult, Options{
		TeamID: "team", AssigneeID: "teammate@example.test", Client: client,
		StateDir: filepath.Join(t.TempDir(), "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Counts.Created != 1 || client.email != "teammate@example.test" || client.input.AssigneeID != "resolved-user" || client.input.ProjectID != "" {
		t.Fatalf("result=%#v client=%#v", result, client)
	}
}

func TestPublishCancellationKeepsHandoffAndPartialReceipt(t *testing.T) {
	record, scanResult := publicationFixture(t, 23)
	ctx, cancel := context.WithCancel(context.Background())
	client := &cancelClient{cancel: cancel}
	state := filepath.Join(t.TempDir(), "state")
	result, err := Publish(ctx, record, scanResult, Options{TeamID: "team", Client: client, StateDir: state})
	if err == nil || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "handoff remains") {
		t.Fatalf("cancellation error = %v", err)
	}
	if len(result.Created) != 1 || result.Counts.Failed != 22 || result.ReceiptPath == "" {
		t.Fatalf("partial result = %#v", result)
	}
	if _, statErr := os.Stat(result.ReceiptPath); statErr != nil {
		t.Fatalf("partial receipt: %v", statErr)
	}
	handoffs, readErr := os.ReadDir(filepath.Join(state, "publications", "handoffs"))
	if readErr != nil || len(handoffs) != 1 {
		t.Fatalf("handoffs = %v, %v", handoffs, readErr)
	}
}

type fakeClient struct {
	mu                                    sync.Mutex
	inFlight                              int
	maxInFlight                           int
	started                               int
	firstFinished                         int
	totalFirstBatch                       int
	failTitle                             string
	barrier                               chan struct{}
	secondBatchStartedBeforeFirstFinished bool
}

func (c *fakeClient) ResolveUser(_ context.Context, email string) (string, error) {
	return "user-for-" + email, nil
}

func (c *fakeClient) CreateIssue(_ context.Context, input linearapi.CreateIssueInput) (linearapi.Issue, error) {
	c.mu.Lock()
	if c.barrier == nil {
		c.barrier = make(chan struct{})
	}
	c.started++
	started := c.started
	c.inFlight++
	if c.inFlight > c.maxInFlight {
		c.maxInFlight = c.inFlight
	}
	if started > c.totalFirstBatch && c.firstFinished < c.totalFirstBatch {
		c.secondBatchStartedBeforeFirstFinished = true
	}
	if started == c.totalFirstBatch {
		close(c.barrier)
	}
	barrier := c.barrier
	c.mu.Unlock()
	if started <= c.totalFirstBatch {
		<-barrier
	}
	c.mu.Lock()
	c.inFlight--
	if started <= c.totalFirstBatch {
		c.firstFinished++
	}
	c.mu.Unlock()
	if input.Title == "[Codex Security][HIGH] "+c.failTitle {
		return linearapi.Issue{}, fmt.Errorf("Linear rejected this finding")
	}
	return linearapi.Issue{Identifier: fmt.Sprintf("SEC-%d", started), URL: fmt.Sprintf("https://linear.app/acme/issue/SEC-%d/x", started)}, nil
}

type cancelClient struct {
	cancel context.CancelFunc
	once   sync.Once
}

type assignmentClient struct {
	email string
	input linearapi.CreateIssueInput
}

func (c *assignmentClient) ResolveUser(_ context.Context, email string) (string, error) {
	c.email = email
	return "resolved-user", nil
}

func (c *assignmentClient) CreateIssue(_ context.Context, input linearapi.CreateIssueInput) (linearapi.Issue, error) {
	c.input = input
	return linearapi.Issue{Identifier: "SEC-1"}, nil
}

func (c *cancelClient) ResolveUser(context.Context, string) (string, error) { return "", nil }

func (c *cancelClient) CreateIssue(ctx context.Context, input linearapi.CreateIssueInput) (linearapi.Issue, error) {
	if strings.HasSuffix(input.Title, " Finding 1") {
		c.once.Do(c.cancel)
		return linearapi.Issue{Identifier: "SEC-1", URL: "https://linear.app/acme/issue/SEC-1/x"}, nil
	}
	<-ctx.Done()
	return linearapi.Issue{}, ctx.Err()
}

func publicationFixture(t *testing.T, count int) (history.Record, *scan.Result) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "scan")
	started := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	completed := started.Add(time.Minute)
	findings := make([]scan.Finding, 0, count)
	for index := 1; index <= count; index++ {
		findings = append(findings, scan.Finding{
			ID: fmt.Sprintf("F-%d", index), Fingerprint: fmt.Sprintf("fingerprint-%d", index),
			Title: fmt.Sprintf("Finding %d", index), Severity: scan.SeverityHigh, Confidence: scan.ConfidenceHigh,
			CWEIDs: []string{"CWE-79"}, Summary: "Summary", Impact: "Impact", Evidence: "Evidence",
			Remediation: "Remediation", AttackPath: "Attack path",
			Locations: []scan.Location{{Path: "src/main.go", StartLine: 10, EndLine: 12, Role: "sink", Snippet: "unsafe(```)"}},
		})
	}
	result := &scan.Result{
		OutDir: out,
		Manifest: scan.ScanManifest{
			SchemaVersion: scan.SchemaVersion, ScanID: "scan-publication", Status: "completed_with_gaps",
			Target: filepath.Join(t.TempDir(), "repository"), TargetMode: "working_tree", TargetRef: "HEAD",
			TargetPaths: []string{"src"}, StartedAt: started, CompletedAt: completed, FindingCount: count,
			ArtifactDigests: map[string]string{"findings.json": "sha256:fixture"},
		},
		Findings: scan.FindingsDocument{SchemaVersion: scan.SchemaVersion, ScanID: "scan-publication", Findings: findings},
		Coverage: scan.CoverageDocument{SchemaVersion: scan.SchemaVersion, ScanID: "scan-publication", Summary: scan.CoverageSummary{Total: 2, Reviewed: 1, Unreviewed: 1}},
	}
	record := history.Record{ScanID: "scan-publication", OutputDir: out, Status: "completed_with_gaps", Target: result.Manifest.Target}
	return record, result
}
