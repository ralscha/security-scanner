package bulk

import (
	"bufio"
	"context"
	"crypto/sha256"
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

	outputpolicy "security-scanner/internal/output"
)

type Job struct {
	ID        string `json:"id"`
	Target    string `json:"target"`
	OutputDir string `json:"output_dir"`
	Context   string `json:"context,omitempty"`
}

type Outcome struct {
	ScanID       string `json:"scan_id,omitempty"`
	OutputDir    string `json:"output_dir,omitempty"`
	Status       string `json:"status"`
	FindingCount int    `json:"finding_count,omitempty"`
}

type JobReceipt struct {
	Job
	Status      string    `json:"status"`
	ScanID      string    `json:"scan_id,omitempty"`
	Attempts    int       `json:"attempts"`
	Error       string    `json:"error,omitempty"`
	StartedAt   time.Time `json:"started_at,omitzero"`
	CompletedAt time.Time `json:"completed_at,omitzero"`
	Cost        float64   `json:"estimated_cost,omitempty"`
	Outcome     Outcome   `json:"outcome,omitzero"`
}

type Entry = JobReceipt

type Receipt struct {
	SchemaVersion string       `json:"schema_version"`
	Status        string       `json:"status"`
	StartedAt     time.Time    `json:"started_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
	ReservedCost  float64      `json:"reserved_cost,omitempty"`
	Jobs          []JobReceipt `json:"jobs"`
	Entries       []Entry      `json:"entries,omitempty"`
}

type Event struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	JobID   string    `json:"job_id,omitempty"`
	Status  string    `json:"status,omitempty"`
	Attempt int       `json:"attempt,omitempty"`
	Message string    `json:"message,omitempty"`
}

type Config struct {
	Workers       int
	MaxRetries    int
	Retries       int
	RetryDelay    time.Duration
	MaxBudget     float64
	EstimatedCost float64
	Resume        bool
	ReceiptPath   string
	OnEvent       func(Event)
	Progress      func(Entry)
}

type Runner func(context.Context, Job) (string, error)

type outcomeRunner func(context.Context, Job) (Outcome, error)

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
	absOutput, err := filepath.Abs(outputDir)
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
		case outcomeRunner:
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
				return scanID, Outcome{ScanID: scanID, OutputDir: job.OutputDir, Status: "completed"}, err
			}
		case func(context.Context, Job) (string, error):
			runner = func(ctx context.Context, job Job) (string, Outcome, error) {
				scanID, err := candidate(ctx, job)
				return scanID, Outcome{ScanID: scanID, OutputDir: job.OutputDir, Status: "completed"}, err
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
	if config.RetryDelay <= 0 {
		config.RetryDelay = time.Second
	}
	if config.MaxBudget < 0 || config.EstimatedCost < 0 {
		return Receipt{}, fmt.Errorf("budget values cannot be negative")
	}
	if config.MaxBudget > 0 && config.EstimatedCost <= 0 {
		return Receipt{}, fmt.Errorf("estimated scan cost must be positive when max budget is set")
	}
	receipt, err := initialReceipt(jobs, config)
	if err != nil {
		return Receipt{}, err
	}
	emit := func(event Event) {
		event.Time = time.Now().UTC()
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
					mu.Lock()
					receipt.Jobs[index].Attempts++
					persistLocked()
					mu.Unlock()
					emit(Event{Type: "job_attempt", JobID: job.ID, Attempt: attempt})
					if runErr == nil || !Transient(runErr) || attempt > config.MaxRetries || ctx.Err() != nil {
						break
					}
					delay := config.RetryDelay * time.Duration(1<<(attempt-1))
					emit(Event{Type: "job_retry", JobID: job.ID, Attempt: attempt, Message: runErr.Error()})
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
				entry.ScanID, entry.CompletedAt = scanID, time.Now().UTC()
				entry.Outcome = outcome
				if runErr == nil {
					entry.Status = "completed"
				} else {
					entry.Status, entry.Error = "failed", runErr.Error()
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
		if entry.Status == "completed" {
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

func initialReceipt(jobs []Job, config Config) (Receipt, error) {
	now := time.Now().UTC()
	receipt := Receipt{SchemaVersion: "1", Status: "running", StartedAt: now, UpdatedAt: now, Jobs: make([]JobReceipt, 0, len(jobs))}
	previous := make(map[string]JobReceipt)
	if config.Resume {
		data, err := os.ReadFile(config.ReceiptPath)
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
		if entry.Status != "completed" {
			entry.Status, entry.Error, entry.ScanID = "pending", "", ""
		}
		receipt.Jobs = append(receipt.Jobs, entry)
		if entry.Status == "completed" {
			receipt.ReservedCost += entry.Cost
		}
	}
	return receipt, nil
}

func finishReceipt(receipt *Receipt, path string, persistenceErr, runErr error) (Receipt, error) {
	receipt.Status = "completed"
	for _, entry := range receipt.Jobs {
		if entry.Status != "completed" {
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

func Transient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
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
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".bulk-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err == nil {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(name, path)
}
