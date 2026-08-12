// Package runstate persists operational scan lifecycle state separately from
// canonical scan results.
package runstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"security-scanner/internal/output"
	"security-scanner/internal/redact"
	"security-scanner/internal/scan"
)

const (
	SchemaVersion = "1"
	StateFile     = "run-state.json"
	JournalFile   = "scan-log.jsonl"
)

const (
	StatusPreparing         = "preparing"
	StatusAnalyzing         = "analyzing"
	StatusRetryWait         = "retry_wait"
	StatusFinalizing        = "finalizing"
	StatusPostScan          = "post_scan"
	StatusCompleted         = "completed"
	StatusCompletedWithGaps = "completed_with_gaps"
	StatusFailed            = "failed"
	StatusInterrupted       = "interrupted"
)

type Session struct {
	SchemaVersion     string    `json:"schema_version"`
	ScanID            string    `json:"scan_id"`
	Status            string    `json:"status"`
	Target            string    `json:"target"`
	OutputDir         string    `json:"output_dir"`
	StartedAt         time.Time `json:"started_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	InventoryDigest   string    `json:"inventory_digest"`
	ConfigFingerprint string    `json:"config_fingerprint"`
	ErrorClass        string    `json:"error_class,omitempty"`
	ErrorSummary      string    `json:"error_summary,omitempty"`
	Attempts          []Attempt `json:"attempts,omitempty"`
}

type Attempt struct {
	Number       int        `json:"number"`
	Status       string     `json:"status"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	ErrorClass   string     `json:"error_class,omitempty"`
	Retryable    bool       `json:"retryable,omitempty"`
	CheckpointID string     `json:"checkpoint_id,omitempty"`
}

type Store struct {
	mu      sync.Mutex
	guard   *output.Guard
	session Session
	now     func() time.Time
}

func Create(guard *output.Guard, session Session) (*Store, error) {
	if guard == nil {
		return nil, fmt.Errorf("private output guard is required")
	}
	if err := scan.ValidateScanID(session.ScanID); err != nil {
		return nil, err
	}
	if session.Status == "" {
		session.Status = StatusPreparing
	}
	if session.Status != StatusPreparing {
		return nil, fmt.Errorf("new scan session must start in %s", StatusPreparing)
	}
	if session.StartedAt.IsZero() {
		return nil, fmt.Errorf("scan session start time is required")
	}
	session.SchemaVersion = SchemaVersion
	session.StartedAt = session.StartedAt.UTC()
	session.UpdatedAt = session.StartedAt
	session.Attempts = append([]Attempt(nil), session.Attempts...)
	store := &Store{guard: guard, session: session, now: time.Now}
	if err := store.writeLocked(); err != nil {
		return nil, err
	}
	return store, nil
}

func Open(guard *output.Guard) (*Store, error) {
	data, err := output.ReadPrivateFile(guard, StateFile)
	if err != nil {
		return nil, fmt.Errorf("read run state: %w", err)
	}
	var session Session
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&session); err != nil {
		return nil, fmt.Errorf("decode run state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("decode run state: trailing data")
	}
	if session.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported run-state schema %q", session.SchemaVersion)
	}
	if err := scan.ValidateScanID(session.ScanID); err != nil {
		return nil, err
	}
	if !knownStatus(session.Status) {
		return nil, fmt.Errorf("invalid run-state status %q", session.Status)
	}
	return &Store{guard: guard, session: session, now: time.Now}, nil
}

func (s *Store) Snapshot() Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSession(s.session)
}

func (s *Store) Transition(status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status == s.session.Status {
		return nil
	}
	if !allowedTransition(s.session.Status, status) {
		return fmt.Errorf("invalid run-state transition %s -> %s", s.session.Status, status)
	}
	s.session.Status = status
	s.session.UpdatedAt = s.now().UTC()
	return s.writeLocked()
}

func (s *Store) Fail(class, summary string, interrupted bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := StatusFailed
	if interrupted {
		status = StatusInterrupted
	}
	if s.session.Status == StatusCompleted || s.session.Status == StatusCompletedWithGaps {
		return fmt.Errorf("terminal success cannot be replaced by %s", status)
	}
	if s.session.Status == status && s.session.ErrorClass == class && s.session.ErrorSummary == redact.Text(summary) {
		return nil
	}
	if !allowedTransition(s.session.Status, status) {
		return fmt.Errorf("invalid run-state transition %s -> %s", s.session.Status, status)
	}
	s.session.Status = status
	s.session.ErrorClass = class
	s.session.ErrorSummary = redact.Text(summary)
	s.session.UpdatedAt = s.now().UTC()
	return s.writeLocked()
}

func (s *Store) StartAttempt(number int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session.Status != StatusAnalyzing {
		return fmt.Errorf("cannot start analysis attempt while session is %s", s.session.Status)
	}
	if number != len(s.session.Attempts)+1 {
		return fmt.Errorf("analysis attempt number must be %d", len(s.session.Attempts)+1)
	}
	now := s.now().UTC()
	s.session.Attempts = append(s.session.Attempts, Attempt{Number: number, Status: "running", StartedAt: now})
	s.session.UpdatedAt = now
	return s.writeLocked()
}

func (s *Store) FinishAttempt(number int, status, errorClass string, retryable bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status != "succeeded" && status != "failed" && status != "interrupted" {
		return fmt.Errorf("invalid attempt terminal status %q", status)
	}
	if number < 1 || number > len(s.session.Attempts) {
		return fmt.Errorf("analysis attempt %d does not exist", number)
	}
	attempt := &s.session.Attempts[number-1]
	if attempt.Number != number {
		return fmt.Errorf("analysis attempt ledger is inconsistent")
	}
	if attempt.Status != "running" {
		if attempt.Status == status && attempt.ErrorClass == errorClass && attempt.Retryable == retryable {
			return nil
		}
		return fmt.Errorf("analysis attempt %d is already %s", number, attempt.Status)
	}
	now := s.now().UTC()
	attempt.Status = status
	attempt.CompletedAt = &now
	attempt.ErrorClass = errorClass
	attempt.Retryable = retryable
	s.session.UpdatedAt = now
	return s.writeLocked()
}

func (s *Store) writeLocked() error {
	if err := s.guard.Validate(); err != nil {
		return fmt.Errorf("validate private output before writing run state: %w", err)
	}
	data, err := json.MarshalIndent(s.session, "", "  ")
	if err != nil {
		return fmt.Errorf("encode run state: %w", err)
	}
	if err := output.WritePrivateFileAtomic(s.guard, StateFile, append(data, '\n')); err != nil {
		return fmt.Errorf("write run state: %w", err)
	}
	return nil
}

func allowedTransition(from, to string) bool {
	allowed := map[string]map[string]bool{
		StatusPreparing:  {StatusAnalyzing: true, StatusFailed: true, StatusInterrupted: true},
		StatusAnalyzing:  {StatusRetryWait: true, StatusFinalizing: true, StatusPostScan: true, StatusFailed: true, StatusInterrupted: true},
		StatusRetryWait:  {StatusAnalyzing: true, StatusFailed: true, StatusInterrupted: true},
		StatusFinalizing: {StatusPostScan: true, StatusCompleted: true, StatusCompletedWithGaps: true, StatusFailed: true},
		StatusPostScan:   {StatusCompleted: true, StatusCompletedWithGaps: true, StatusFailed: true},
	}
	return allowed[from][to]
}

func knownStatus(status string) bool {
	switch status {
	case StatusPreparing, StatusAnalyzing, StatusRetryWait, StatusFinalizing, StatusPostScan,
		StatusCompleted, StatusCompletedWithGaps, StatusFailed, StatusInterrupted:
		return true
	default:
		return false
	}
}

func cloneSession(session Session) Session {
	clone := session
	clone.Attempts = append([]Attempt(nil), session.Attempts...)
	return clone
}

// Journal atomically persists the complete redacted event snapshot on every
// record, avoiding unsafe append behavior.
type Journal struct {
	mu     sync.Mutex
	guard  *output.Guard
	events []scan.ActivityEvent
}

func NewJournal(guard *output.Guard, buffered []scan.ActivityEvent) (*Journal, error) {
	journal := &Journal{guard: guard, events: append([]scan.ActivityEvent(nil), buffered...)}
	for i := range journal.events {
		journal.events[i].Message = redact.Text(journal.events[i].Message)
	}
	if err := journal.writeLocked(); err != nil {
		return nil, err
	}
	return journal, nil
}

func (j *Journal) Record(event scan.ActivityEvent) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	event.Timestamp = event.Timestamp.UTC()
	event.Message = redact.Text(event.Message)
	j.events = append(j.events, event)
	return j.writeLocked()
}

func (j *Journal) Snapshot() []scan.ActivityEvent {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]scan.ActivityEvent(nil), j.events...)
}

func (j *Journal) writeLocked() error {
	if j.guard == nil {
		return fmt.Errorf("private output guard is required")
	}
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	for _, event := range j.events {
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("encode activity journal: %w", err)
		}
	}
	if err := output.WritePrivateFileAtomic(j.guard, JournalFile, data.Bytes()); err != nil {
		return fmt.Errorf("write activity journal: %w", err)
	}
	return nil
}

// Exists reports whether a run-state file exists without weakening private
// directory validation.
func Exists(guard *output.Guard) (bool, error) {
	_, err := output.ReadPrivateFile(guard, StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
