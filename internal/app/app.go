package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino/components/model"

	"security-scanner/internal/agent"
	"security-scanner/internal/history"
	"security-scanner/internal/knowledgebase"
	"security-scanner/internal/llm"
	"security-scanner/internal/output"
	"security-scanner/internal/postscan"
	"security-scanner/internal/recovery"
	"security-scanner/internal/redact"
	"security-scanner/internal/runstate"
	"security-scanner/internal/scan"
)

type Options struct {
	Target                        string
	OutputDir                     string
	Provider                      string
	Model                         string
	APIKey                        string
	BaseURL                       string
	APIVersion                    string
	MaxOutputTokens               int
	UserContext                   string
	Excludes                      []string
	Includes                      []string
	TargetMode                    string
	TargetRef                     string
	ArchiveExisting               bool
	AuthMode                      string
	MaxFileBytes                  int64
	MaxIterations                 int
	MaxAgentConcurrency           int
	RequestTimeout                time.Duration
	MaxDuration                   time.Duration
	FailOnSeverity                string
	ScanPrompt                    string
	FollowUpPrompt                string
	KnowledgeBasePaths            []string
	KnowledgeBaseMaxDocuments     int
	KnowledgeBaseMaxDocumentBytes int64
	KnowledgeBaseMaxTotalBytes    int64
	PostScanPrompt                string
	PostScanOn                    string
	PostScanFailureMode           string
	PostScanMaxDuration           time.Duration
	PostScanMaxIterations         int
	MaxAnalysisAttempts           int
	AnalysisRetryBaseDelay        time.Duration
	Progress                      func(string)
	PostScanRunner                postscan.Runner
	RetryRandom                   func() float64
	RetryAfter                    func(time.Duration) <-chan time.Time
	AnalyzerFactory               func(model.BaseChatModel, agent.Config, *scan.Inventory, *agent.ReadTracker) Analyzer
}

type Analyzer interface {
	Analyze(context.Context, string) (scan.Submission, error)
}

type Preparation struct {
	Target        string                  `json:"target"`
	OutputDir     string                  `json:"output_dir"`
	Model         llm.Config              `json:"-"`
	Provider      string                  `json:"provider"`
	ModelName     string                  `json:"model"`
	Inventory     *scan.Inventory         `json:"inventory"`
	KnowledgeBase *knowledgebase.Prepared `json:"knowledge_base,omitempty"`
}

type activityLog struct {
	mu      sync.Mutex
	events  []scan.ActivityEvent
	journal *runstate.Journal
	scanID  string
	err     error
}

func (log *activityLog) record(timestamp time.Time, event, message string) {
	log.recordEvent(scan.ActivityEvent{Timestamp: timestamp.UTC(), Event: event, Message: message})
}

func (log *activityLog) recordEvent(entry scan.ActivityEvent) {
	log.mu.Lock()
	defer log.mu.Unlock()
	entry.Timestamp = entry.Timestamp.UTC()
	entry.Message = redact.Text(entry.Message)
	if entry.ScanID == "" {
		entry.ScanID = log.scanID
	}
	log.events = append(log.events, entry)
	if log.journal != nil && log.err == nil {
		log.err = log.journal.Record(entry)
	}
}

func (log *activityLog) snapshot() []scan.ActivityEvent {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]scan.ActivityEvent(nil), log.events...)
}

func (log *activityLog) attach(guard *output.Guard, scanID string) error {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.scanID = scanID
	for index := range log.events {
		if log.events[index].ScanID == "" {
			log.events[index].ScanID = scanID
		}
	}
	journal, err := runstate.NewJournal(guard, log.events)
	if err != nil {
		return err
	}
	log.journal = journal
	return nil
}

func (log *activityLog) error() error {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.err
}

type PostScanError struct{ Err error }

func (e *PostScanError) Error() string { return "post-scan failed: " + e.Err.Error() }
func (e *PostScanError) Unwrap() error { return e.Err }

type AnalysisError struct {
	Err      error
	Attempts int
}

func (e *AnalysisError) Error() string { return e.Err.Error() }
func (e *AnalysisError) Unwrap() error { return e.Err }

func AttemptsFromError(err error) int {
	var analysisErr *AnalysisError
	if errors.As(err, &analysisErr) {
		return analysisErr.Attempts
	}
	return 0
}

func Run(ctx context.Context, opts Options) (*scan.Result, error) {
	started := time.Now().UTC()
	activity := &activityLog{}
	activity.record(started, "scan.started", "")
	progress := opts.Progress
	opts.Progress = func(message string) {
		activity.record(time.Now(), "scan.progress", message)
		if progress != nil {
			progress(message)
		}
	}
	if opts.MaxAgentConcurrency < 0 {
		return nil, fmt.Errorf("max agent concurrency cannot be negative")
	}
	if opts.MaxAgentConcurrency == 0 {
		opts.MaxAgentConcurrency = 4
	}
	if opts.MaxFileBytes < 0 {
		return nil, fmt.Errorf("max file bytes cannot be negative")
	}
	if opts.MaxIterations <= 0 {
		opts.MaxIterations = 80
	}
	if opts.MaxAnalysisAttempts <= 0 {
		opts.MaxAnalysisAttempts = 1
	}
	if opts.AnalysisRetryBaseDelay <= 0 {
		opts.AnalysisRetryBaseDelay = time.Second
	}
	if opts.PostScanOn == "" {
		opts.PostScanOn = "success"
	}
	if opts.PostScanFailureMode == "" {
		opts.PostScanFailureMode = "warn"
	}
	if opts.PostScanMaxDuration <= 0 {
		opts.PostScanMaxDuration = 5 * time.Minute
	}
	if opts.PostScanMaxIterations <= 0 {
		opts.PostScanMaxIterations = 10
	}
	if opts.MaxAnalysisAttempts < 1 {
		return nil, fmt.Errorf("max analysis attempts must be positive")
	}
	if !validPostScanOn(opts.PostScanOn) {
		return nil, fmt.Errorf("post-scan trigger must be success, gaps, failure, or all")
	}
	if opts.PostScanFailureMode != "warn" && opts.PostScanFailureMode != "fail" {
		return nil, fmt.Errorf("post-scan failure mode must be warn or fail")
	}
	prepared, err := Prepare(opts, started)
	if err != nil {
		return nil, err
	}
	if archived, err := output.Prepare(prepared.OutputDir, opts.ArchiveExisting, started); err != nil {
		return nil, err
	} else if archived != "" && opts.Progress != nil {
		opts.Progress("archived existing output to " + archived)
	}
	outputGuard, err := output.PreparePrivateDir(prepared.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("prepare private output directory: %w", err)
	}
	chatModel, resolvedModel, err := llm.DefaultRegistry().Build(ctx, prepared.Model)
	if err != nil {
		return nil, err
	}
	chatModel, err = llm.LimitConcurrency(chatModel, opts.MaxAgentConcurrency)
	if err != nil {
		return nil, err
	}
	scanID := scan.AllocateScanID(prepared.Inventory.Root, started)
	launchConfig := launchConfiguration(opts, resolvedModel, prepared)
	fingerprint, err := configurationFingerprint(opts, resolvedModel, prepared)
	if err != nil {
		return nil, fmt.Errorf("fingerprint scan configuration: %w", err)
	}
	state, err := runstate.Create(outputGuard, runstate.Session{
		ScanID: scanID, Status: runstate.StatusPreparing, Target: prepared.Target, OutputDir: prepared.OutputDir,
		StartedAt: started, InventoryDigest: scan.InventoryDigest(prepared.Inventory), ConfigFingerprint: fingerprint,
	})
	if err != nil {
		return nil, fmt.Errorf("create durable scan session: %w", err)
	}
	if err := activity.attach(outputGuard, scanID); err != nil {
		return nil, fmt.Errorf("create activity journal: %w", err)
	}
	store, err := history.DefaultStore()
	if err != nil {
		return nil, err
	}
	historyRecord := history.Record{
		ScanID: scanID, Target: prepared.Target, OutputDir: prepared.OutputDir, Status: runstate.StatusPreparing,
		Provider: resolvedModel.Provider, Model: resolvedModel.Model, StartedAt: started,
		TargetMode: opts.TargetMode, TargetRef: opts.TargetRef, TargetPaths: append([]string(nil), opts.Includes...),
		LaunchConfig: launchConfig,
	}
	if err := store.Upsert(historyRecord); err != nil {
		return nil, fmt.Errorf("register scan history session: %w", err)
	}
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("using %s model %s", resolvedModel.Provider, resolvedModel.Model))
		opts.Progress(fmt.Sprintf("inventory contains %d files", len(prepared.Inventory.Files)))
	}
	preparationDuration := time.Since(started)
	analysisStarted := time.Now()
	if err := state.Transition(runstate.StatusAnalyzing); err != nil {
		return nil, err
	}
	historyRecord.Status = runstate.StatusAnalyzing
	if err := store.Upsert(historyRecord); err != nil {
		return nil, fmt.Errorf("update scan history session: %w", err)
	}
	var tracker *agent.ReadTracker
	var submission scan.Submission
	var primaryErr error
	var primaryClass recovery.Class
	for attempt := 1; attempt <= opts.MaxAnalysisAttempts; attempt++ {
		if err := verifyInputs(prepared); err != nil {
			primaryErr = recovery.Wrap(recovery.ClassInventoryDrift, false, err)
			primaryClass = recovery.ClassInventoryDrift
			break
		}
		if err := state.StartAttempt(attempt); err != nil {
			return nil, err
		}
		activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "analysis.attempt.started", Phase: "analysis", Attempt: attempt})
		tracker = agent.NewReadTracker()
		agentConfig := agent.Config{
			MaxIterations: opts.MaxIterations, Progress: opts.Progress, ScanPrompt: opts.ScanPrompt,
			FollowUpPrompt: opts.FollowUpPrompt, KnowledgeBase: prepared.KnowledgeBase,
		}
		var analyzer Analyzer
		if opts.AnalyzerFactory != nil {
			analyzer = opts.AnalyzerFactory(chatModel, agentConfig, prepared.Inventory, tracker)
		} else {
			analyzer = agent.NewEinoAnalyzer(chatModel, agentConfig, prepared.Inventory, tracker)
		}
		if analyzer == nil {
			return nil, fmt.Errorf("analysis factory returned nil analyzer")
		}
		submission, err = analyzer.Analyze(ctx, opts.UserContext)
		if err == nil {
			if err := state.FinishAttempt(attempt, "succeeded", "", false); err != nil {
				return nil, err
			}
			activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "analysis.attempt.succeeded", Phase: "analysis", Attempt: attempt})
			primaryErr = nil
			break
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		primaryClass, retryable := recovery.Classify(err)
		if errors.Is(err, agent.ErrNoSubmission) {
			primaryClass, retryable = recovery.ClassInvalidSubmission, false
		}
		primaryErr = recovery.Wrap(primaryClass, retryable, err)
		attemptStatus := "failed"
		if primaryClass == recovery.ClassCanceled || primaryClass == recovery.ClassDeadline {
			attemptStatus = "interrupted"
		}
		if finishErr := state.FinishAttempt(attempt, attemptStatus, string(primaryClass), retryable); finishErr != nil {
			return nil, finishErr
		}
		activity.recordEvent(scan.ActivityEvent{
			Timestamp: time.Now(), Event: "analysis.attempt.failed", Phase: "analysis", Attempt: attempt,
			ErrorClass: string(primaryClass), Retryable: new(retryable), Message: err.Error(),
		})
		if ctx.Err() != nil || !retryable || attempt == opts.MaxAnalysisAttempts {
			break
		}
		if verifyErr := verifyInputs(prepared); verifyErr != nil {
			primaryClass = recovery.ClassInventoryDrift
			primaryErr = recovery.Wrap(primaryClass, false, verifyErr)
			break
		}
		if err := state.Transition(runstate.StatusRetryWait); err != nil {
			return nil, err
		}
		historyRecord.Status = runstate.StatusRetryWait
		if err := store.Upsert(historyRecord); err != nil {
			return nil, fmt.Errorf("update scan history retry state: %w", err)
		}
		delay := recovery.Backoff(opts.AnalysisRetryBaseDelay, attempt, opts.RetryRandom)
		activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "analysis.retry_scheduled", Phase: "analysis", Attempt: attempt, Message: delay.String()})
		if err := recovery.Wait(ctx, delay, opts.RetryAfter); err != nil {
			primaryClass, _ = recovery.Classify(err)
			primaryErr = recovery.Wrap(primaryClass, false, err)
			break
		}
		if err := state.Transition(runstate.StatusAnalyzing); err != nil {
			return nil, err
		}
		historyRecord.Status = runstate.StatusAnalyzing
		if err := store.Upsert(historyRecord); err != nil {
			return nil, fmt.Errorf("update scan history analysis state: %w", err)
		}
	}
	if primaryErr == nil && ctx.Err() != nil {
		primaryClass, _ = recovery.Classify(ctx.Err())
		primaryErr = recovery.Wrap(primaryClass, false, ctx.Err())
	}
	if primaryErr != nil {
		if shouldRunPostScan(opts, "failure") && eligibleFailurePostScan(primaryClass, ctx) {
			_ = state.Transition(runstate.StatusPostScan)
			activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "post_scan.started", Phase: "post_scan", ErrorClass: string(primaryClass)})
			if postErr := executePostScan(ctx, opts, chatModel, prepared, outputGuard, postscan.Config{
				ScanID: scanID, Prompt: opts.PostScanPrompt, Trigger: "failure", MaxIterations: opts.PostScanMaxIterations,
				Inventory: prepared.Inventory, KnowledgeBase: prepared.KnowledgeBase, FailureClass: string(primaryClass), Failure: redact.Text(primaryErr.Error()),
			}); postErr != nil {
				postClass, _ := recovery.Classify(postErr)
				activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "post_scan.failed", Phase: "post_scan", ErrorClass: string(postClass), Message: postErr.Error()})
			} else {
				activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "post_scan.completed", Phase: "post_scan"})
			}
		} else if strings.TrimSpace(opts.PostScanPrompt) != "" {
			activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "post_scan.skipped", Phase: "post_scan", Message: "failure is not eligible for post-scan execution"})
		}
		interrupted := primaryClass == recovery.ClassCanceled || primaryClass == recovery.ClassDeadline
		terminalEvent := "scan.failed"
		if interrupted {
			terminalEvent = "scan.interrupted"
		}
		activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: terminalEvent, Phase: "analysis", ErrorClass: string(primaryClass), Message: primaryErr.Error()})
		_ = state.Fail(string(primaryClass), primaryErr.Error(), interrupted)
		historyRecord.Status = state.Snapshot().Status
		historyRecord.ErrorClass = string(primaryClass)
		_ = store.Upsert(historyRecord)
		if journalErr := activity.error(); journalErr != nil {
			return nil, &AnalysisError{Err: errors.Join(primaryErr, journalErr), Attempts: len(state.Snapshot().Attempts)}
		}
		return nil, &AnalysisError{Err: primaryErr, Attempts: len(state.Snapshot().Attempts)}
	}
	if opts.Progress != nil {
		opts.Progress("validating and writing scan artifacts")
	}
	if err := verifyInputs(prepared); err != nil {
		wrapped := recovery.Wrap(recovery.ClassInventoryDrift, false, err)
		activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "scan.failed", Phase: "finalizing", ErrorClass: string(recovery.ClassInventoryDrift), Message: err.Error()})
		_ = state.Fail(string(recovery.ClassInventoryDrift), wrapped.Error(), false)
		historyRecord.Status = runstate.StatusFailed
		historyRecord.ErrorClass = string(recovery.ClassInventoryDrift)
		_ = store.Upsert(historyRecord)
		return nil, wrapped
	}
	if err := state.Transition(runstate.StatusFinalizing); err != nil {
		return nil, err
	}
	result, err := scan.Finalize(prepared.Inventory, tracker, submission, scan.FinalizeOptions{
		ScanID:              scanID,
		OutputDir:           prepared.OutputDir,
		Provider:            resolvedModel.Provider,
		Model:               resolvedModel.Model,
		StartedAt:           started,
		TargetMode:          opts.TargetMode,
		TargetRef:           opts.TargetRef,
		TargetPaths:         opts.Includes,
		PreparationDuration: preparationDuration,
		AnalysisDuration:    time.Since(analysisStarted),
		OutputGuard:         outputGuard,
		Activity:            activity.snapshot(),
		LaunchConfig:        launchConfig,
	})
	if err != nil {
		class := recovery.ClassInternal
		var invalid *scan.InvalidSubmissionError
		var drift *scan.InventoryDriftError
		if errors.As(err, &invalid) {
			class = recovery.ClassInvalidSubmission
		} else if errors.As(err, &drift) {
			class = recovery.ClassInventoryDrift
		}
		activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "scan.failed", Phase: "finalizing", ErrorClass: string(class), Message: err.Error()})
		_ = state.Fail(string(class), err.Error(), false)
		historyRecord.Status = runstate.StatusFailed
		historyRecord.ErrorClass = string(class)
		_ = store.Upsert(historyRecord)
		return nil, err
	}
	if err := store.Add(result); err != nil {
		return nil, fmt.Errorf("record scan history: %w", err)
	}
	result.AnalysisAttempts = len(state.Snapshot().Attempts)
	if len(result.Activity) > 0 {
		activity.recordEvent(result.Activity[len(result.Activity)-1])
	}
	terminalStatus := runstate.StatusCompleted
	trigger := "success"
	if result.Manifest.Status == runstate.StatusCompletedWithGaps {
		terminalStatus = runstate.StatusCompletedWithGaps
	}
	if result.Manifest.Status == runstate.StatusCompletedWithGaps || len(result.Findings.Gaps) > 0 {
		trigger = "gaps"
	}
	var postErr error
	if shouldRunPostScan(opts, trigger) && ctx.Err() == nil {
		if err := state.Transition(runstate.StatusPostScan); err != nil {
			return result, err
		}
		activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "post_scan.started", Phase: "post_scan"})
		postErr = executePostScan(ctx, opts, chatModel, prepared, outputGuard, postscan.Config{
			ScanID: scanID, Prompt: opts.PostScanPrompt, Trigger: trigger, MaxIterations: opts.PostScanMaxIterations,
			Inventory: prepared.Inventory, KnowledgeBase: prepared.KnowledgeBase, Canonical: result,
		})
		if postErr != nil {
			activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "post_scan.failed", Phase: "post_scan", Message: postErr.Error()})
		} else {
			activity.recordEvent(scan.ActivityEvent{Timestamp: time.Now(), Event: "post_scan.completed", Phase: "post_scan"})
		}
	}
	if err := state.Transition(terminalStatus); err != nil {
		return result, err
	}
	if journalErr := activity.error(); journalErr != nil {
		return result, journalErr
	}
	if postErr != nil {
		if opts.PostScanFailureMode == "fail" {
			return result, &PostScanError{Err: postErr}
		}
		result.Warnings = append(result.Warnings, "post-scan failed: "+redact.Text(postErr.Error()))
	}
	return result, nil
}

func launchConfiguration(opts Options, resolved llm.Config, prepared *Preparation) *scan.LaunchConfiguration {
	config := &scan.LaunchConfiguration{
		AuthMode: resolved.AuthMode, RequiresExplicitAPIKey: strings.TrimSpace(opts.APIKey) != "",
		BaseURL: resolved.BaseURL, APIVersion: resolved.APIVersion, MaxOutputTokens: resolved.MaxOutputTokens,
		UserContext: opts.UserContext, ScanPrompt: opts.ScanPrompt, FollowUpPrompt: opts.FollowUpPrompt,
		PostScanPrompt: opts.PostScanPrompt, PostScanOn: opts.PostScanOn, PostScanFailureMode: opts.PostScanFailureMode,
		PostScanMaxDuration: durationString(opts.PostScanMaxDuration), PostScanMaxIterations: opts.PostScanMaxIterations,
		Excludes: append([]string(nil), opts.Excludes...), MaxFileBytes: opts.MaxFileBytes,
		MaxIterations: opts.MaxIterations, MaxAgentConcurrency: opts.MaxAgentConcurrency,
		RequestTimeout: resolved.Timeout.String(), MaxDuration: durationString(opts.MaxDuration),
		FailOnSeverity: strings.TrimSpace(opts.FailOnSeverity), MaxAnalysisAttempts: opts.MaxAnalysisAttempts,
		AnalysisRetryBaseDelay: durationString(opts.AnalysisRetryBaseDelay),
	}
	if prepared != nil && prepared.KnowledgeBase != nil {
		config.KnowledgeBasePaths = append([]string(nil), prepared.KnowledgeBase.SourceRoots...)
		limits, _ := knowledgebase.NormalizeOptions(knowledgebase.Options{
			MaxDocuments: opts.KnowledgeBaseMaxDocuments, MaxDocumentBytes: opts.KnowledgeBaseMaxDocumentBytes,
			MaxTotalBytes: opts.KnowledgeBaseMaxTotalBytes,
		})
		config.KnowledgeBaseMaxDocuments = limits.MaxDocuments
		config.KnowledgeBaseMaxDocumentBytes = limits.MaxDocumentBytes
		config.KnowledgeBaseMaxTotalBytes = limits.MaxTotalBytes
	}
	return config
}

func configurationFingerprint(opts Options, resolved llm.Config, prepared *Preparation) (string, error) {
	knowledgeDigest := ""
	knowledgeDocuments := []string{}
	if prepared.KnowledgeBase != nil {
		knowledgeDigest = prepared.KnowledgeBase.Digest
		for _, document := range prepared.KnowledgeBase.Documents {
			knowledgeDocuments = append(knowledgeDocuments, document.ID+":"+document.SHA256)
		}
	}
	includes := append([]string(nil), opts.Includes...)
	excludes := append([]string(nil), opts.Excludes...)
	sort.Strings(includes)
	sort.Strings(excludes)
	payload := struct {
		Root, Mode, Ref, Inventory, KnowledgeDigest                   string
		Includes, Excludes, KnowledgeDocuments                        []string
		Provider, Model, BaseURL, APIVersion, AuthMode                string
		MaxOutputTokens, Concurrency, MaxIterations                   int
		MaxAnalysisAttempts, PostScanMaxIterations                    int
		MaxFileBytes, KnowledgeBaseMaxDocumentBytes                   int64
		KnowledgeBaseMaxTotalBytes                                    int64
		KnowledgeBaseMaxDocuments                                     int
		RequestTimeout                                                string
		PostScanOn, PostScanFailureMode, PostScanMaxDuration          string
		AnalysisRetryBaseDelay                                        string
		UserContext, ScanPrompt, FollowUpPrompt, PostScanPrompt       string
		PromptVersion, RecoverySchema, EinoVersion, CheckpointVersion string
	}{
		Root: prepared.Target, Mode: opts.TargetMode, Ref: opts.TargetRef, Inventory: scan.InventoryDigest(prepared.Inventory),
		KnowledgeDigest: knowledgeDigest, Includes: includes, Excludes: excludes,
		KnowledgeDocuments: knowledgeDocuments, Provider: resolved.Provider, Model: resolved.Model, BaseURL: resolved.BaseURL,
		APIVersion: resolved.APIVersion, AuthMode: resolved.AuthMode, MaxOutputTokens: resolved.MaxOutputTokens,
		Concurrency: opts.MaxAgentConcurrency, RequestTimeout: resolved.Timeout.String(), UserContext: opts.UserContext,
		MaxIterations: opts.MaxIterations, MaxAnalysisAttempts: opts.MaxAnalysisAttempts, MaxFileBytes: opts.MaxFileBytes,
		KnowledgeBaseMaxDocuments: opts.KnowledgeBaseMaxDocuments, KnowledgeBaseMaxDocumentBytes: opts.KnowledgeBaseMaxDocumentBytes,
		KnowledgeBaseMaxTotalBytes: opts.KnowledgeBaseMaxTotalBytes, PostScanMaxIterations: opts.PostScanMaxIterations,
		PostScanOn: opts.PostScanOn, PostScanFailureMode: opts.PostScanFailureMode, PostScanMaxDuration: durationString(opts.PostScanMaxDuration),
		AnalysisRetryBaseDelay: durationString(opts.AnalysisRetryBaseDelay),
		ScanPrompt:             opts.ScanPrompt, FollowUpPrompt: opts.FollowUpPrompt, PostScanPrompt: opts.PostScanPrompt,
		PromptVersion: "primary-v1", RecoverySchema: runstate.SchemaVersion, EinoVersion: "v0.9.13", CheckpointVersion: "unsupported-v1",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:]), nil
}

func verifyInputs(prepared *Preparation) error {
	if err := scan.VerifyInventory(prepared.Inventory); err != nil {
		return err
	}
	if prepared.KnowledgeBase != nil {
		if err := knowledgebase.Verify(prepared.KnowledgeBase); err != nil {
			return err
		}
	}
	return nil
}

func executePostScan(ctx context.Context, opts Options, chatModel model.BaseChatModel, prepared *Preparation, guard *output.Guard, config postscan.Config) (err error) {
	if err := verifyInputs(prepared); err != nil {
		return err
	}
	canonicalBefore, err := canonicalArtifactDigests(guard)
	if err != nil {
		return err
	}
	defer func() {
		if ownershipErr := verifyCanonicalArtifactDigests(guard, canonicalBefore); ownershipErr != nil {
			err = errors.Join(err, ownershipErr)
		}
	}()
	postCtx := ctx
	if opts.PostScanMaxDuration > 0 {
		var cancel context.CancelFunc
		postCtx, cancel = context.WithTimeout(ctx, opts.PostScanMaxDuration)
		defer cancel()
	}
	runner := opts.PostScanRunner
	if runner == nil {
		runner = postscan.NewEinoRunner(chatModel)
	}
	result, err := runner.Run(postCtx, config)
	if err != nil {
		return err
	}
	if result.ScanID != config.ScanID || result.Trigger != config.Trigger {
		return fmt.Errorf("post-scan result identity or trigger does not match the scan session")
	}
	if err := verifyInputs(prepared); err != nil {
		return err
	}
	return postscan.WriteArtifacts(guard, result)
}

var canonicalArtifactNames = []string{"findings.json", "coverage.json", "report.md", "results.sarif"}

func canonicalArtifactDigests(guard *output.Guard) (map[string]string, error) {
	digests := make(map[string]string, len(canonicalArtifactNames))
	for _, name := range canonicalArtifactNames {
		data, err := output.ReadPrivateFile(guard, name)
		if errors.Is(err, os.ErrNotExist) {
			digests[name] = "missing"
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read canonical artifact %s before post-scan: %w", name, err)
		}
		digest := sha256.Sum256(data)
		digests[name] = fmt.Sprintf("%x", digest[:])
	}
	return digests, nil
}

func verifyCanonicalArtifactDigests(guard *output.Guard, before map[string]string) error {
	after, err := canonicalArtifactDigests(guard)
	if err != nil {
		return err
	}
	for _, name := range canonicalArtifactNames {
		if before[name] != after[name] {
			return fmt.Errorf("post-scan pass changed canonical artifact %s", name)
		}
	}
	return nil
}

func validPostScanOn(value string) bool {
	switch value {
	case "success", "gaps", "failure", "all":
		return true
	default:
		return false
	}
}

func shouldRunPostScan(opts Options, trigger string) bool {
	return strings.TrimSpace(opts.PostScanPrompt) != "" && (opts.PostScanOn == trigger || opts.PostScanOn == "all")
}

func eligibleFailurePostScan(class recovery.Class, ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	switch class {
	case recovery.ClassConfiguration, recovery.ClassAuthentication, recovery.ClassDeadline, recovery.ClassCanceled,
		recovery.ClassInventoryDrift, recovery.ClassCheckpoint:
		return false
	default:
		return true
	}
}

func durationString(duration time.Duration) string {
	if duration <= 0 {
		return ""
	}
	return duration.String()
}

// Prepare validates a scan and freezes its inventory without constructing or calling a model.
func Prepare(opts Options, started time.Time) (*Preparation, error) {
	if opts.Target == "" {
		opts.Target = "."
	}
	absTarget, err := filepath.Abs(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	absTarget, err = filepath.EvalSymlinks(absTarget)
	if err != nil {
		return nil, fmt.Errorf("resolve target symlinks: %w", err)
	}
	if opts.OutputDir == "" {
		opts.OutputDir, err = output.DefaultScanDir(absTarget, started)
		if err != nil {
			return nil, err
		}
	} else if opts.OutputDir, err = filepath.Abs(opts.OutputDir); err != nil {
		return nil, fmt.Errorf("resolve output directory: %w", err)
	}
	if samePath(absTarget, opts.OutputDir) {
		return nil, fmt.Errorf("output directory cannot be the scan target")
	}
	if err := rejectOutputSymlinks(absTarget, opts.OutputDir); err != nil {
		return nil, err
	}
	if opts.OutputDir, err = output.Validate(context.Background(), absTarget, opts.OutputDir, opts.ArchiveExisting); err != nil {
		return nil, err
	}
	if opts.MaxFileBytes < 0 {
		return nil, fmt.Errorf("max file bytes cannot be negative")
	}
	resolvedModel, err := llm.DefaultRegistry().Resolve(llm.Config{
		Provider:        opts.Provider,
		Model:           opts.Model,
		APIKey:          opts.APIKey,
		BaseURL:         opts.BaseURL,
		APIVersion:      opts.APIVersion,
		MaxOutputTokens: opts.MaxOutputTokens,
		Timeout:         opts.RequestTimeout,
		AuthMode:        opts.AuthMode,
	})
	if err != nil {
		return nil, err
	}
	if opts.Progress != nil {
		opts.Progress("building fixed file inventory")
	}
	inventory, err := scan.BuildInventory(absTarget, scan.InventoryOptions{
		MaxFileBytes: opts.MaxFileBytes,
		OutputDir:    opts.OutputDir,
		Excludes:     opts.Excludes,
		Includes:     opts.Includes,
	})
	if err != nil {
		return nil, err
	}
	if len(inventory.Files) == 0 {
		return nil, fmt.Errorf("target contains no files after exclusions")
	}
	knowledgeOptions, err := knowledgebase.NormalizeOptions(knowledgebase.Options{
		MaxDocuments:     opts.KnowledgeBaseMaxDocuments,
		MaxDocumentBytes: opts.KnowledgeBaseMaxDocumentBytes,
		MaxTotalBytes:    opts.KnowledgeBaseMaxTotalBytes,
	})
	if err != nil {
		return nil, err
	}
	var preparedKnowledge *knowledgebase.Prepared
	if len(opts.KnowledgeBasePaths) > 0 {
		if opts.Progress != nil {
			opts.Progress("building fixed knowledge-base inventory")
		}
		preparedKnowledge, err = knowledgebase.Prepare(opts.KnowledgeBasePaths, knowledgeOptions)
		if err != nil {
			return nil, err
		}
		if opts.Progress != nil {
			opts.Progress(fmt.Sprintf("knowledge base contains %d documents", len(preparedKnowledge.Documents)))
		}
	}
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("inventory contains %d files", len(inventory.Files)))
	}
	return &Preparation{
		Target: absTarget, OutputDir: opts.OutputDir, Model: resolvedModel,
		Provider: resolvedModel.Provider, ModelName: resolvedModel.Model, Inventory: inventory, KnowledgeBase: preparedKnowledge,
	}, nil
}

func samePath(left, right string) bool {
	rel, err := filepath.Rel(filepath.Clean(left), filepath.Clean(right))
	return err == nil && rel == "."
}

func rejectOutputSymlinks(root, output string) error {
	rel, err := filepath.Rel(root, output)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	current := root
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect output path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output path inside target traverses symlink: %s", current)
		}
	}
	return nil
}
