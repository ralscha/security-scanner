package bulk

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"

	outputpolicy "security-scanner/internal/output"
	"security-scanner/internal/recovery"
	"security-scanner/internal/redact"
)

type Job struct {
	ID        string `json:"id"`
	Target    string `json:"target"`
	OutputDir string `json:"output_dir"`
	Context   string `json:"context,omitempty"`
}

type Outcome struct {
	ScanID           string `json:"scan_id,omitempty"`
	OutputDir        string `json:"output_dir,omitempty"`
	Status           string `json:"status"`
	FindingCount     int    `json:"finding_count,omitempty"`
	AnalysisAttempts int    `json:"analysis_attempts,omitempty"`
}

type JobReceipt struct {
	Job
	Status                   string    `json:"status"`
	ScanID                   string    `json:"scan_id,omitempty"`
	Attempts                 int       `json:"attempts"`
	OuterJobMaxAttempts      int       `json:"outer_job_max_attempts,omitempty"`
	InnerAnalysisMaxAttempts int       `json:"inner_analysis_max_attempts,omitempty"`
	InnerAnalysisAttempts    int       `json:"inner_analysis_attempts,omitempty"`
	Error                    string    `json:"error,omitempty"`
	StartedAt                time.Time `json:"started_at,omitzero"`
	CompletedAt              time.Time `json:"completed_at,omitzero"`
	Cost                     float64   `json:"estimated_cost,omitempty"`
	Outcome                  Outcome   `json:"outcome,omitzero"`
}

type Entry = JobReceipt

type Receipt struct {
	SchemaVersion            string       `json:"schema_version"`
	Status                   string       `json:"status"`
	StartedAt                time.Time    `json:"started_at"`
	UpdatedAt                time.Time    `json:"updated_at"`
	ReservedCost             float64      `json:"reserved_cost,omitempty"`
	OuterJobMaxAttempts      int          `json:"outer_job_max_attempts,omitempty"`
	InnerAnalysisMaxAttempts int          `json:"inner_analysis_max_attempts,omitempty"`
	Jobs                     []JobReceipt `json:"jobs"`
	Entries                  []Entry      `json:"entries,omitempty"`
}

type Event struct {
	Time                     time.Time `json:"time"`
	Type                     string    `json:"type"`
	JobID                    string    `json:"job_id,omitempty"`
	Status                   string    `json:"status,omitempty"`
	Attempt                  int       `json:"attempt,omitempty"`
	OuterJobMaxAttempts      int       `json:"outer_job_max_attempts,omitempty"`
	InnerAnalysisMaxAttempts int       `json:"inner_analysis_max_attempts,omitempty"`
	InnerAnalysisAttempts    int       `json:"inner_analysis_attempts,omitempty"`
	Message                  string    `json:"message,omitempty"`
}

type Config struct {
	Workers                  int
	MaxRetries               int
	Retries                  int
	RetryDelay               time.Duration
	MaxBudget                float64
	EstimatedCost            float64
	Resume                   bool
	ReceiptPath              string
	OnEvent                  func(Event)
	Progress                 func(Entry)
	InnerAnalysisMaxAttempts int
}

type Runner func(context.Context, Job) (string, error)

type OutcomeRunner func(context.Context, Job) (Outcome, error)

const (
	StatusCompleted         = "completed"
	StatusCompletedWithGaps = "completed_with_gaps"
)

func ParseInput(path string) ([]Job, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bulk input: %w", err)
	}
	var jobs []Job
	if json.Unmarshal(data, &jobs) == nil && jobs != nil {
		return normalizeJobs(jobs)
	}
	jobs = nil
	var targets []string
	if json.Unmarshal(data, &targets) == nil && targets != nil {
		for _, target := range targets {
			jobs = append(jobs, Job{Target: target})
		}
		return normalizeJobs(jobs)
	}
	if csvJobs, recognized, err := parseCSVInput(data, strings.EqualFold(filepath.Ext(path), ".csv")); err != nil {
		return nil, fmt.Errorf("parse bulk CSV: %w", err)
	} else if recognized {
		return normalizeJobs(csvJobs)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			jobs = append(jobs, Job{Target: line})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse bulk input: %w", err)
	}
	return normalizeJobs(jobs)
}

func parseCSVInput(data []byte, required bool) ([]Job, bool, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		if required {
			return nil, true, err
		}
		return nil, false, nil
	}
	if len(records) == 0 {
		return nil, required, nil
	}
	targetColumn, contextColumn := -1, -1
	for column, raw := range records[0] {
		header := strings.TrimSpace(raw)
		if column == 0 {
			header = strings.TrimPrefix(header, "\ufeff")
		}
		switch strings.ToLower(header) {
		case "target", "repository", "path":
			if targetColumn >= 0 {
				return nil, true, fmt.Errorf("CSV contains multiple target or repository columns")
			}
			targetColumn = column
		case "context":
			if contextColumn >= 0 {
				return nil, true, fmt.Errorf("CSV contains multiple context columns")
			}
			contextColumn = column
		}
	}
	if targetColumn < 0 {
		if required {
			return nil, true, fmt.Errorf("CSV requires a target or repository column")
		}
		return nil, false, nil
	}
	if !required && len(records[0]) == 1 {
		return nil, false, nil
	}
	jobs := make([]Job, 0, len(records)-1)
	for rowNumber, record := range records[1:] {
		if targetColumn >= len(record) {
			return nil, true, fmt.Errorf("row %d has no repository value", rowNumber+2)
		}
		target := strings.TrimSpace(record[targetColumn])
		contextValue := ""
		if contextColumn >= 0 && contextColumn < len(record) {
			contextValue = strings.TrimSpace(record[contextColumn])
		}
		if target == "" {
			blank := true
			for _, value := range record {
				blank = blank && strings.TrimSpace(value) == ""
			}
			if blank {
				continue
			}
			return nil, true, fmt.Errorf("row %d has an empty repository value", rowNumber+2)
		}
		jobs = append(jobs, Job{Target: target, Context: contextValue})
	}
	return jobs, true, nil
}

func normalizeJobs(jobs []Job) ([]Job, error) {
	if len(jobs) == 0 {
		return nil, fmt.Errorf("bulk input contains no repositories")
	}
	seen := make(map[string]struct{}, len(jobs))
	result := make([]Job, 0, len(jobs))
	for _, job := range jobs {
		target := strings.TrimSpace(job.Target)
		if target == "" {
			return nil, fmt.Errorf("bulk input contains an empty repository")
		}
		absolute, err := filepath.Abs(target)
		if err != nil {
			return nil, err
		}
		absolute, err = filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, fmt.Errorf("resolve repository %q: %w", job.Target, err)
		}
		key := pathKey(absolute)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		digest := sha256.Sum256([]byte(key))
		job.ID, job.Target, job.Context = fmt.Sprintf("repo-%x", digest[:8]), absolute, strings.TrimSpace(job.Context)
		result = append(result, job)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func BuildJobs(targets []string, outputDir string) ([]Job, error) {
	input := make([]Job, 0, len(targets))
	for _, target := range targets {
		input = append(input, Job{Target: target})
	}
	return PrepareJobs(input, outputDir)
}

func PrepareJobs(jobs []Job, outputDir string) ([]Job, error) {
	normalized, err := normalizeJobs(jobs)
	if err != nil {
		return nil, err
	}
	absOutput, err := outputpolicy.ResolvePath(outputDir)
	if err != nil {
		return nil, fmt.Errorf("resolve bulk output directory: %w", err)
	}
	result := make([]Job, 0, len(normalized))
	for _, job := range normalized {
		info, err := os.Stat(job.Target)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("repository target is not a directory: %s", job.Target)
		}
		if err := outputpolicy.ValidateBoundary(context.Background(), job.Target, absOutput); err != nil {
			return nil, err
		}
		job.OutputDir = filepath.Join(absOutput, job.ID)
		result = append(result, job)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func pathKey(path string) string {
	key := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		return strings.ToLower(key)
	}
	return key
}

func Run(ctx context.Context, jobs []Job, third, fourth any) (Receipt, error) {
	var config Config
	var runner func(context.Context, Job) (string, Outcome, error)
	legacyOrder := false
	switch value := third.(type) {
	case Config:
		legacyOrder = true
		config = value
		switch candidate := fourth.(type) {
		case func(context.Context, Job) (Outcome, error):
			runner = func(ctx context.Context, job Job) (string, Outcome, error) {
				outcome, err := candidate(ctx, job)
				return outcome.ScanID, outcome, err
			}
		case OutcomeRunner:
			runner = func(ctx context.Context, job Job) (string, Outcome, error) {
				outcome, err := candidate(ctx, job)
				return outcome.ScanID, outcome, err
			}
		}
	default:
		resolvedConfig, ok := fourth.(Config)
		if !ok {
			return Receipt{}, fmt.Errorf("bulk configuration is required")
		}
		config = resolvedConfig
		switch candidate := third.(type) {
		case Runner:
			runner = func(ctx context.Context, job Job) (string, Outcome, error) {
				scanID, err := candidate(ctx, job)
				return scanID, Outcome{ScanID: scanID, OutputDir: job.OutputDir, Status: StatusCompleted}, err
			}
		case func(context.Context, Job) (string, error):
			runner = func(ctx context.Context, job Job) (string, Outcome, error) {
				scanID, err := candidate(ctx, job)
				return scanID, Outcome{ScanID: scanID, OutputDir: job.OutputDir, Status: StatusCompleted}, err
			}
		case OutcomeRunner:
			runner = func(ctx context.Context, job Job) (string, Outcome, error) {
				outcome, err := candidate(ctx, job)
				return outcome.ScanID, outcome, err
			}
		case func(context.Context, Job) (Outcome, error):
			runner = func(ctx context.Context, job Job) (string, Outcome, error) {
				outcome, err := candidate(ctx, job)
				return outcome.ScanID, outcome, err
			}
		}
	}
	if runner == nil {
		return Receipt{}, fmt.Errorf("bulk runner is required")
	}
	if config.MaxRetries == 0 && config.Retries > 0 {
		config.MaxRetries = config.Retries
	}
	if config.Workers <= 0 {
		config.Workers = 1
	}
	if config.Workers > 64 {
		return Receipt{}, fmt.Errorf("workers cannot exceed 64")
	}
	if config.MaxRetries < 0 || config.MaxRetries > 10 {
		return Receipt{}, fmt.Errorf("max retries must be between 0 and 10")
	}
	if config.InnerAnalysisMaxAttempts <= 0 {
		config.InnerAnalysisMaxAttempts = 1
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = time.Second
	}
	if config.MaxBudget < 0 || config.EstimatedCost < 0 {
		return Receipt{}, fmt.Errorf("budget values cannot be negative")
	}
	if config.MaxBudget > 0 && config.EstimatedCost <= 0 {
		return Receipt{}, fmt.Errorf("estimated scan cost must be positive when max budget is set")
	}
	supervisor, err := acquireSupervisorLock(config.ReceiptPath)
	if err != nil {
		return Receipt{}, err
	}
	defer func() { _ = supervisor.Close() }()
	receipt, err := initialReceipt(jobs, config)
	if err != nil {
		return Receipt{}, err
	}
	emit := func(event Event) {
		event.Time = time.Now().UTC()
		event.OuterJobMaxAttempts = config.MaxRetries + 1
		event.InnerAnalysisMaxAttempts = config.InnerAnalysisMaxAttempts
		if config.OnEvent != nil {
			config.OnEvent(event)
		}
	}
	var mu sync.Mutex
	var persistenceErr error
	persistLocked := func() {
		receipt.UpdatedAt = time.Now().UTC()
		receipt.Entries = append(receipt.Entries[:0], receipt.Jobs...)
		if err := saveReceipt(config.ReceiptPath, receipt); err != nil && persistenceErr == nil {
			persistenceErr = err
		}
	}
	queue := make(chan int)
	var group sync.WaitGroup
	for range config.Workers {
		group.Go(func() {
			for index := range queue {
				mu.Lock()
				entry := &receipt.Jobs[index]
				entry.Status, entry.Error, entry.StartedAt = "running", "", time.Now().UTC()
				entry.Cost = config.EstimatedCost
				persistLocked()
				job := entry.Job
				innerAttempts := entry.InnerAnalysisAttempts
				if config.Progress != nil {
					config.Progress(*entry)
				}
				mu.Unlock()
				emit(Event{Type: "job_started", JobID: job.ID, Status: "running"})
				var scanID string
				var outcome Outcome
				var runErr error
				for attempt := 1; attempt <= config.MaxRetries+1; attempt++ {
					scanID, outcome, runErr = runner(ctx, job)
					innerAttempts += outcome.AnalysisAttempts
					mu.Lock()
					receipt.Jobs[index].Attempts++
					persistLocked()
					mu.Unlock()
					emit(Event{Type: "job_attempt", JobID: job.ID, Attempt: attempt, InnerAnalysisAttempts: outcome.AnalysisAttempts})
					if runErr == nil || !Transient(runErr) || attempt > config.MaxRetries || ctx.Err() != nil {
						break
					}
					delay := config.RetryDelay * time.Duration(1<<(attempt-1))
					emit(Event{Type: "job_retry", JobID: job.ID, Attempt: attempt, Message: redact.Text(runErr.Error())})
					timer := time.NewTimer(delay)
					select {
					case <-ctx.Done():
						runErr = ctx.Err()
						timer.Stop()
					case <-timer.C:
					}
				}
				mu.Lock()
				entry = &receipt.Jobs[index]
				if outcome.ScanID == "" {
					outcome.ScanID = scanID
				}
				if outcome.OutputDir == "" {
					outcome.OutputDir = job.OutputDir
				}
				outcome.AnalysisAttempts = innerAttempts
				entry.InnerAnalysisAttempts = innerAttempts
				entry.ScanID, entry.CompletedAt = outcome.ScanID, time.Now().UTC()
				entry.Outcome = outcome
				if runErr == nil {
					switch outcome.Status {
					case "", StatusCompleted:
						entry.Status = StatusCompleted
						entry.Outcome.Status = StatusCompleted
					case StatusCompletedWithGaps:
						entry.Status = StatusCompletedWithGaps
					default:
						entry.Status = "failed"
						entry.Error = fmt.Sprintf("unsupported bulk outcome status %q", outcome.Status)
					}
				} else {
					entry.Status, entry.Error = "failed", redact.Text(runErr.Error())
				}
				persistLocked()
				status, message := entry.Status, entry.Error
				if config.Progress != nil {
					config.Progress(*entry)
				}
				mu.Unlock()
				emit(Event{Type: "job_finished", JobID: job.ID, Status: status, Message: message})
			}
		})
	}
	plannedCost := receipt.ReservedCost
	for index := range receipt.Jobs {
		mu.Lock()
		entry := &receipt.Jobs[index]
		if sealedStatus(entry.Status) {
			mu.Unlock()
			continue
		}
		if config.MaxBudget > 0 && plannedCost+config.EstimatedCost > config.MaxBudget {
			entry.Status, entry.Error = "budget_exceeded", "estimated budget exhausted before scheduling"
			mu.Unlock()
			continue
		}
		plannedCost += config.EstimatedCost
		mu.Unlock()
		select {
		case queue <- index:
		case <-ctx.Done():
			close(queue)
			group.Wait()
			return finishReceipt(&receipt, config.ReceiptPath, persistenceErr, ctx.Err())
		}
	}
	close(queue)
	group.Wait()
	receipt.ReservedCost = plannedCost
	finished, finishErr := finishReceipt(&receipt, config.ReceiptPath, persistenceErr, nil)
	if legacyOrder && finishErr != nil && persistenceErr == nil && ctx.Err() == nil {
		return finished, nil
	}
	return finished, finishErr
}

func acquireSupervisorLock(receiptPath string) (*flock.Flock, error) {
	if strings.TrimSpace(receiptPath) == "" {
		return nil, fmt.Errorf("receipt path is required")
	}
	absReceipt, err := filepath.Abs(receiptPath)
	if err != nil {
		return nil, fmt.Errorf("resolve bulk receipt path: %w", err)
	}
	if _, err := outputpolicy.EnsurePrivateDir(filepath.Dir(absReceipt)); err != nil {
		return nil, fmt.Errorf("prepare bulk supervisor directory: %w", err)
	}
	lockPath := absReceipt + ".lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("prepare bulk supervisor lock: %w", err)
	}
	opened, statErr := file.Stat()
	closeErr := file.Close()
	named, lstatErr := os.Lstat(lockPath)
	if statErr != nil || closeErr != nil || lstatErr != nil {
		return nil, fmt.Errorf("inspect bulk supervisor lock: %w", errors.Join(statErr, closeErr, lstatErr))
	}
	if !opened.Mode().IsRegular() || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, named) {
		return nil, fmt.Errorf("bulk supervisor lock must be a non-symlink regular file: %s", lockPath)
	}
	if err := outputpolicy.SecurePrivateFile(lockPath); err != nil {
		return nil, fmt.Errorf("secure bulk supervisor lock: %w", err)
	}
	supervisor := flock.New(lockPath, flock.SetFlag(os.O_CREATE|os.O_RDWR), flock.SetPermissions(0o600))
	locked, err := supervisor.TryLock()
	if err != nil {
		_ = supervisor.Close()
		return nil, fmt.Errorf("acquire bulk supervisor lock: %w", err)
	}
	if !locked {
		_ = supervisor.Close()
		return nil, fmt.Errorf("bulk supervisor is already running for receipt: %s", absReceipt)
	}
	return supervisor, nil
}

func initialReceipt(jobs []Job, config Config) (Receipt, error) {
	now := time.Now().UTC()
	receipt := Receipt{SchemaVersion: "1", Status: "running", StartedAt: now, UpdatedAt: now, Jobs: make([]JobReceipt, 0, len(jobs)), OuterJobMaxAttempts: config.MaxRetries + 1, InnerAnalysisMaxAttempts: config.InnerAnalysisMaxAttempts}
	previous := make(map[string]JobReceipt)
	if config.Resume {
		guard, err := outputpolicy.EnsurePrivateDir(filepath.Dir(config.ReceiptPath))
		if err != nil {
			return Receipt{}, fmt.Errorf("prepare private receipt directory: %w", err)
		}
		data, err := outputpolicy.ReadPrivateFile(guard, filepath.Base(config.ReceiptPath))
		if err != nil && !os.IsNotExist(err) {
			return Receipt{}, fmt.Errorf("read bulk receipt: %w", err)
		}
		if err == nil {
			var saved Receipt
			if err := json.Unmarshal(data, &saved); err != nil {
				return Receipt{}, fmt.Errorf("decode bulk receipt: %w", err)
			}
			if len(saved.Jobs) == 0 {
				saved.Jobs = append(saved.Jobs, saved.Entries...)
			}
			for _, entry := range saved.Jobs {
				previous[entry.ID] = entry
			}
		}
	}
	for _, job := range jobs {
		entry := previous[job.ID]
		entry.Job = job
		entry.OuterJobMaxAttempts = config.MaxRetries + 1
		entry.InnerAnalysisMaxAttempts = config.InnerAnalysisMaxAttempts
		if legacyIncompleteOutcome(entry) {
			entry.Status, entry.Error = StatusCompletedWithGaps, ""
			entry.Outcome.Status = StatusCompletedWithGaps
			entry.Outcome.ScanID = entry.ScanID
			entry.Outcome.OutputDir = entry.OutputDir
		}
		if !sealedStatus(entry.Status) {
			entry.Status, entry.Error, entry.ScanID = "pending", "", ""
			entry.Outcome = Outcome{}
		}
		receipt.Jobs = append(receipt.Jobs, entry)
		if sealedStatus(entry.Status) {
			receipt.ReservedCost += entry.Cost
		}
	}
	return receipt, nil
}

func finishReceipt(receipt *Receipt, path string, persistenceErr, runErr error) (Receipt, error) {
	receipt.Status = StatusCompleted
	for _, entry := range receipt.Jobs {
		if entry.Status == StatusCompletedWithGaps {
			if receipt.Status == StatusCompleted {
				receipt.Status = StatusCompletedWithGaps
			}
			continue
		}
		if entry.Status != StatusCompleted {
			receipt.Status = "incomplete"
			if runErr == nil {
				runErr = fmt.Errorf("one or more bulk jobs did not complete")
			}
		}
	}
	receipt.UpdatedAt = time.Now().UTC()
	receipt.Entries = append(receipt.Entries[:0], receipt.Jobs...)
	if err := saveReceipt(path, *receipt); err != nil && persistenceErr == nil {
		persistenceErr = err
	}
	if persistenceErr != nil {
		return *receipt, fmt.Errorf("persist bulk receipt: %w", persistenceErr)
	}
	return *receipt, runErr
}

func sealedStatus(status string) bool {
	return status == StatusCompleted || status == StatusCompletedWithGaps
}

func legacyIncompleteOutcome(entry JobReceipt) bool {
	if entry.Status != "failed" || !strings.HasPrefix(strings.ToLower(entry.Error), "incomplete coverage:") {
		return false
	}
	guard, err := outputpolicy.OpenPrivateDir(entry.OutputDir)
	if err != nil {
		return false
	}
	manifestData, err := outputpolicy.ReadPrivateFile(guard, "scan-manifest.json")
	if err != nil {
		return false
	}
	var manifest struct {
		ScanID    string            `json:"scan_id"`
		Status    string            `json:"status"`
		Artifacts map[string]string `json:"artifacts"`
	}
	if json.Unmarshal(manifestData, &manifest) != nil || manifest.ScanID != entry.ScanID || manifest.Status != StatusCompletedWithGaps {
		return false
	}
	coverageData, err := outputpolicy.ReadPrivateFile(guard, "coverage.json")
	if err != nil {
		return false
	}
	var coverage struct {
		Summary struct {
			Unreviewed int `json:"unreviewed"`
		} `json:"summary"`
	}
	if json.Unmarshal(coverageData, &coverage) != nil || coverage.Summary.Unreviewed <= 0 {
		return false
	}
	for _, name := range manifest.Artifacts {
		if filepath.Base(name) != name {
			return false
		}
		if _, err := outputpolicy.ReadPrivateFile(guard, name); err != nil {
			return false
		}
	}
	return len(manifest.Artifacts) > 0
}

func Transient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var classified *recovery.Error
	if errors.As(err, &classified) {
		return classified.Retryable
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"429", "500", "502", "503", "504", "timeout", "temporarily unavailable", "connection reset", "connection refused", "rate limit"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func saveReceipt(path string, receipt Receipt) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("receipt path is required")
	}
	guard, err := outputpolicy.EnsurePrivateDir(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("prepare private receipt directory: %w", err)
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return outputpolicy.WritePrivateFileAtomic(guard, filepath.Base(path), append(data, '\n'))
}
