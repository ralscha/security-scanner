package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/model"

	"security-scanner/internal/agent"
	"security-scanner/internal/history"
	"security-scanner/internal/llm"
	"security-scanner/internal/postscan"
	"security-scanner/internal/scan"
)

func TestRejectOutputSymlinksInsideTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks commonly requires elevated Windows privileges")
	}
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, ".scanner")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := rejectOutputSymlinks(root, filepath.Join(link, "scan")); err == nil {
		t.Fatal("expected symlinked output path to be rejected")
	}
}

func TestPrepareRejectsOutputInsideTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(root, "reports")
	_, err := Prepare(Options{
		Target:    root,
		OutputDir: outputDir,
		Provider:  "ollama",
		Model:     "test-model",
		AuthMode:  "none",
	}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "must be disjoint") {
		t.Fatalf("output boundary error = %v", err)
	}
}

func TestPrepareDoesNotImposeAnImplicitSourceSizeLimit(t *testing.T) {
	root := t.TempDir()
	large := filepath.Join(root, "large.go")
	if err := os.WriteFile(large, []byte("package large\n/*"+strings.Repeat("x", 1024*1024)+"*/\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	prepared, err := Prepare(Options{
		Target:   root,
		Provider: "ollama",
		Model:    "test-model",
		AuthMode: "none",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Inventory.Files) != 1 || !prepared.Inventory.Files[0].Reviewable {
		t.Fatalf("large source file was implicitly skipped: %#v", prepared.Inventory.Files)
	}
}

func TestPrepareRejectsNegativeSourceSizeLimit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Prepare(Options{Target: root, MaxFileBytes: -1}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "max file bytes cannot be negative") {
		t.Fatalf("expected negative source size limit error, got %v", err)
	}
}

func TestSamePath(t *testing.T) {
	root := t.TempDir()
	if !samePath(root, filepath.Join(root, ".")) {
		t.Fatal("equivalent paths should compare equal")
	}
}

func TestActivityLogRedactsPersistedMessages(t *testing.T) {
	log := &activityLog{}
	log.record(time.Unix(100, 0), "scan.progress", "authorization=Bearer synthetic-secret-value")
	events := log.snapshot()
	if len(events) != 1 || events[0].Event != "scan.progress" || strings.Contains(events[0].Message, "synthetic-secret-value") || !strings.Contains(events[0].Message, "[redacted]") {
		t.Fatalf("unexpected activity events: %#v", events)
	}
}

type analyzerFunc func(context.Context, string) (scan.Submission, error)

func (f analyzerFunc) Analyze(ctx context.Context, input string) (scan.Submission, error) {
	return f(ctx, input)
}

type retryStatusError int

func (e retryStatusError) Error() string   { return "temporary provider failure" }
func (e retryStatusError) StatusCode() int { return int(e) }

func TestRunRetriesWithFreshTrackerAndPersistsOneIdentity(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("SECURITY_SCANNER_STATE_DIR", stateDir)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "scan")
	attempts := 0
	result, err := Run(context.Background(), Options{
		Target: root, OutputDir: out, Provider: "ollama", Model: "test", AuthMode: "none",
		MaxAnalysisAttempts: 2, AnalysisRetryBaseDelay: time.Millisecond,
		RetryRandom: func() float64 { return 0 }, RetryAfter: func(time.Duration) <-chan time.Time {
			ready := make(chan time.Time, 1)
			ready <- time.Now()
			return ready
		},
		AnalyzerFactory: func(_ model.BaseChatModel, _ agent.Config, _ *scan.Inventory, tracker *agent.ReadTracker) Analyzer {
			attempts++
			current := attempts
			return analyzerFunc(func(context.Context, string) (scan.Submission, error) {
				if current == 1 {
					return scan.Submission{}, retryStatusError(503)
				}
				tracker.Mark("app.go", 1, 1)
				return scan.Submission{ThreatModel: "Untrusted callers."}, nil
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || result.AnalysisAttempts != 2 || result.Manifest.Status != "completed" {
		t.Fatalf("attempts=%d result=%#v", attempts, result.Manifest)
	}
	stateData, err := os.ReadFile(filepath.Join(out, "run-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		ScanID   string `json:"scan_id"`
		Status   string `json:"status"`
		Attempts []any  `json:"attempts"`
	}
	if err := json.Unmarshal(stateData, &state); err != nil {
		t.Fatal(err)
	}
	if state.ScanID != result.Manifest.ScanID || state.ScanID != result.Findings.ScanID || state.ScanID != result.Coverage.ScanID || state.Status != "completed" || len(state.Attempts) != 2 {
		t.Fatalf("inconsistent durable identity/state: %#v", state)
	}
	store, err := history.DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(result.Manifest.ScanID)
	if err != nil || record.ScanID != state.ScanID {
		t.Fatalf("history record=%#v error=%v", record, err)
	}
}

func TestRunFailureLeavesOnlyPrivateOperationalArtifacts(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("SECURITY_SCANNER_STATE_DIR", stateDir)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "scan")
	result, err := Run(context.Background(), Options{
		Target: root, OutputDir: out, Provider: "ollama", Model: "test", AuthMode: "none",
		AnalyzerFactory: func(_ model.BaseChatModel, _ agent.Config, _ *scan.Inventory, _ *agent.ReadTracker) Analyzer {
			return analyzerFunc(func(context.Context, string) (scan.Submission, error) {
				return scan.Submission{}, errors.New("Authorization: Bearer synthetic-secret")
			})
		},
	})
	if err == nil || result != nil {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if AttemptsFromError(err) != 1 {
		t.Fatalf("attempt count was not preserved in error: %v", err)
	}
	for _, name := range []string{"run-state.json", "scan-log.jsonl"} {
		data, readErr := os.ReadFile(filepath.Join(out, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(data), "synthetic-secret") {
			t.Fatalf("secret persisted in %s: %s", name, data)
		}
	}
	for _, name := range []string{"findings.json", "coverage.json", "report.md", "results.sarif", "scan-manifest.json"} {
		if _, statErr := os.Stat(filepath.Join(out, name)); !os.IsNotExist(statErr) {
			t.Fatalf("canonical artifact %s exists after failure: %v", name, statErr)
		}
	}
	store, err := history.DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	records, err := store.List(root)
	if err != nil || len(records) != 1 || records[0].Status != "failed" {
		t.Fatalf("failed session history = %#v, %v", records, err)
	}
	prefix := records[0].ScanID[:len(records[0].ScanID)-2]
	record, err := store.Get(prefix)
	if err != nil || record.ScanID != records[0].ScanID {
		t.Fatalf("failed session prefix lookup = %#v, %v", record, err)
	}
	if log, err := history.LoadLogs(record); err != nil || len(log.Events) == 0 {
		t.Fatalf("failed session log = %#v, %v", log, err)
	}
}

type postScanRunnerFunc func(context.Context, postscan.Config) (postscan.Result, error)

func (f postScanRunnerFunc) Run(ctx context.Context, config postscan.Config) (postscan.Result, error) {
	return f(ctx, config)
}

func TestRunReturnsCanonicalResultWhenPostScanFailModeFails(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_STATE_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), Options{
		Target: root, OutputDir: filepath.Join(t.TempDir(), "scan"), Provider: "ollama", Model: "test", AuthMode: "none",
		PostScanPrompt: "Recommend next steps.", PostScanOn: "success", PostScanFailureMode: "fail",
		AnalyzerFactory: func(_ model.BaseChatModel, _ agent.Config, _ *scan.Inventory, tracker *agent.ReadTracker) Analyzer {
			return analyzerFunc(func(context.Context, string) (scan.Submission, error) {
				tracker.Mark("app.go", 1, 1)
				return scan.Submission{ThreatModel: "Untrusted callers."}, nil
			})
		},
		PostScanRunner: postScanRunnerFunc(func(context.Context, postscan.Config) (postscan.Result, error) {
			return postscan.Result{}, errors.New("advisory unavailable")
		}),
	})
	var postErr *PostScanError
	if result == nil || !errors.As(err, &postErr) {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if _, statErr := os.Stat(filepath.Join(result.OutDir, "scan-manifest.json")); statErr != nil {
		t.Fatalf("canonical manifest was not retained: %v", statErr)
	}
}

func TestRunWritesSeparatePostScanArtifactsAfterCanonicalSuccess(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_STATE_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), Options{
		Target: root, OutputDir: filepath.Join(t.TempDir(), "scan"), Provider: "ollama", Model: "test", AuthMode: "none",
		PostScanPrompt: "Recommend next steps.", PostScanOn: "success", PostScanFailureMode: "warn",
		AnalyzerFactory: func(_ model.BaseChatModel, _ agent.Config, _ *scan.Inventory, tracker *agent.ReadTracker) Analyzer {
			return analyzerFunc(func(context.Context, string) (scan.Submission, error) {
				tracker.Mark("app.go", 1, 1)
				return scan.Submission{ThreatModel: "Untrusted callers."}, nil
			})
		},
		PostScanRunner: postScanRunnerFunc(func(_ context.Context, config postscan.Config) (postscan.Result, error) {
			now := time.Now().UTC()
			return postscan.Result{SchemaVersion: postscan.SchemaVersion, ScanID: config.ScanID, Trigger: config.Trigger, Summary: "Next steps.", StartedAt: now, CompletedAt: now}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"post-scan.json", "post-scan.md"} {
		if _, err := os.Stat(filepath.Join(result.OutDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	manifestData, err := os.ReadFile(filepath.Join(result.OutDir, "scan-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest scan.ScanManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, exists := manifest.Artifacts["post_scan"]; exists {
		t.Fatalf("advisory artifacts leaked into canonical manifest: %s", manifestData)
	}
}

func TestRunExecutesFailurePostScanButKeepsPrimaryErrorAuthoritative(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_STATE_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "scan")
	primary := errors.New("primary analysis failed")
	result, err := Run(context.Background(), Options{
		Target: root, OutputDir: out, Provider: "ollama", Model: "test", AuthMode: "none",
		PostScanPrompt: "Explain next steps.", PostScanOn: "failure",
		AnalyzerFactory: func(_ model.BaseChatModel, _ agent.Config, _ *scan.Inventory, _ *agent.ReadTracker) Analyzer {
			return analyzerFunc(func(context.Context, string) (scan.Submission, error) { return scan.Submission{}, primary })
		},
		PostScanRunner: postScanRunnerFunc(func(_ context.Context, config postscan.Config) (postscan.Result, error) {
			now := time.Now().UTC()
			return postscan.Result{SchemaVersion: postscan.SchemaVersion, ScanID: config.ScanID, Trigger: config.Trigger, Summary: "Retry later.", StartedAt: now, CompletedAt: now}, nil
		}),
	})
	if result != nil || !errors.Is(err, primary) {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	for _, name := range []string{"post-scan.json", "post-scan.md"} {
		if _, statErr := os.Stat(filepath.Join(out, name)); statErr != nil {
			t.Fatal(statErr)
		}
	}
	if _, statErr := os.Stat(filepath.Join(out, "scan-manifest.json")); !os.IsNotExist(statErr) {
		t.Fatalf("failure advisory fabricated canonical manifest: %v", statErr)
	}
}

func TestRunCancellationSchedulesNeitherRetryNorPostScan(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_STATE_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	postCalls := 0
	analyzerCalls := 0
	_, err := Run(ctx, Options{
		Target: root, OutputDir: filepath.Join(t.TempDir(), "scan"), Provider: "ollama", Model: "test", AuthMode: "none",
		MaxAnalysisAttempts: 3, PostScanPrompt: "Explain.", PostScanOn: "all",
		AnalyzerFactory: func(_ model.BaseChatModel, _ agent.Config, _ *scan.Inventory, _ *agent.ReadTracker) Analyzer {
			analyzerCalls++
			return analyzerFunc(func(context.Context, string) (scan.Submission, error) {
				cancel()
				return scan.Submission{}, retryStatusError(503)
			})
		},
		PostScanRunner: postScanRunnerFunc(func(context.Context, postscan.Config) (postscan.Result, error) {
			postCalls++
			return postscan.Result{}, nil
		}),
	})
	if !errors.Is(err, context.Canceled) || analyzerCalls != 1 || postCalls != 0 {
		t.Fatalf("error=%v analyzer_calls=%d post_calls=%d", err, analyzerCalls, postCalls)
	}
}

func TestRunStopsRetryWhenRepositoryDriftsBetweenAttempts(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_STATE_DIR", t.TempDir())
	root := t.TempDir()
	path := filepath.Join(root, "app.go")
	if err := os.WriteFile(path, []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	result, err := Run(context.Background(), Options{
		Target: root, OutputDir: filepath.Join(t.TempDir(), "scan"), Provider: "ollama", Model: "test", AuthMode: "none",
		MaxAnalysisAttempts: 3,
		AnalyzerFactory: func(_ model.BaseChatModel, _ agent.Config, _ *scan.Inventory, _ *agent.ReadTracker) Analyzer {
			attempts++
			return analyzerFunc(func(context.Context, string) (scan.Submission, error) {
				if err := os.WriteFile(path, []byte("package changed\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return scan.Submission{}, retryStatusError(503)
			})
		},
	})
	if result != nil || err == nil || attempts != 1 || !strings.Contains(err.Error(), "changed after inventory") {
		t.Fatalf("result=%#v error=%v attempts=%d", result, err, attempts)
	}
}

func TestConfigurationFingerprintExcludesAPIKeyAndIncludesPrompts(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory, err := scan.BuildInventory(root, scan.InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	prepared := &Preparation{Target: root, Inventory: inventory}
	opts := Options{ScanPrompt: "scan", FollowUpPrompt: "follow", PostScanPrompt: "post", MaxAgentConcurrency: 4}
	left, err := configurationFingerprint(opts, llm.Config{Provider: "openai", Model: "model", APIKey: "first"}, prepared)
	if err != nil {
		t.Fatal(err)
	}
	right, err := configurationFingerprint(opts, llm.Config{Provider: "openai", Model: "model", APIKey: "second"}, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatal("API key changed the compatibility fingerprint")
	}
	opts.PostScanPrompt = "different"
	changed, err := configurationFingerprint(opts, llm.Config{Provider: "openai", Model: "model", APIKey: "second"}, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if changed == left {
		t.Fatal("prompt change did not change the compatibility fingerprint")
	}
}
