package triage

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"security-scanner/internal/output"
)

type Decision struct {
	OccurrenceID string    `json:"occurrence_id"`
	Fingerprint  string    `json:"fingerprint"`
	ScanID       string    `json:"scan_id"`
	Target       string    `json:"target"`
	Disposition  string    `json:"disposition"`
	Reason       string    `json:"reason"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type document struct {
	SchemaVersion string     `json:"schema_version"`
	Decisions     []Decision `json:"decisions"`
}

type Store struct{ path string }

func DefaultStore() (*Store, error) {
	state, err := output.StateDir()
	if err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(state, "triage", "decisions.json")}, nil
}

func NewStore(path string) *Store { return &Store{path: path} }

func ParseOccurrenceID(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	separator := strings.LastIndex(value, ":")
	if separator <= 0 || separator == len(value)-1 {
		return "", "", fmt.Errorf("occurrence ID must be SCAN_ID:FINDING_ID")
	}
	scanID, findingID := value[:separator], value[separator+1:]
	if !strings.HasPrefix(scanID, "scan-") || !strings.HasPrefix(findingID, "F-") {
		return "", "", fmt.Errorf("occurrence ID must be SCAN_ID:FINDING_ID")
	}
	return scanID, findingID, nil
}

func (s *Store) SetFalsePositive(occurrenceID, reason string, now time.Time) (Decision, error) {
	scanID, findingID, err := ParseOccurrenceID(occurrenceID)
	if err != nil {
		return Decision{}, err
	}
	decision := Decision{OccurrenceID: occurrenceID, ScanID: scanID, Reason: reason, UpdatedAt: now.UTC()}
	if err := s.setFalsePositive(decision); err != nil {
		return Decision{}, err
	}
	_ = findingID
	decision.Disposition = "false_positive"
	return decision, nil
}

func (s *Store) SetDecision(decision Decision) error { return s.setFalsePositive(decision) }

func (s *Store) setFalsePositive(decision Decision) error {
	decision.OccurrenceID = strings.TrimSpace(decision.OccurrenceID)
	decision.Fingerprint = strings.TrimSpace(decision.Fingerprint)
	decision.Reason = strings.TrimSpace(decision.Reason)
	if decision.OccurrenceID == "" || decision.ScanID == "" {
		return fmt.Errorf("occurrence and scan are required")
	}
	if decision.Reason == "" {
		return fmt.Errorf("false-positive reason is required")
	}
	decision.Disposition = "false_positive"
	if decision.UpdatedAt.IsZero() {
		decision.UpdatedAt = time.Now().UTC()
	}
	doc, err := s.load()
	if err != nil {
		return err
	}
	key := decisionKey(decision)
	replaced := false
	for i := range doc.Decisions {
		if decisionKey(doc.Decisions[i]) == key {
			doc.Decisions[i] = decision
			replaced = true
			break
		}
	}
	if !replaced {
		doc.Decisions = append(doc.Decisions, decision)
	}
	sort.Slice(doc.Decisions, func(i, j int) bool { return doc.Decisions[i].UpdatedAt.After(doc.Decisions[j].UpdatedAt) })
	return s.save(doc)
}

func (s *Store) List() ([]Decision, error) {
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	return doc.Decisions, nil
}

func (s *Store) load() (document, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return document{SchemaVersion: "1", Decisions: []Decision{}}, nil
	}
	if err != nil {
		return document{}, fmt.Errorf("read triage store: %w", err)
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return document{}, fmt.Errorf("decode triage store: %w", err)
	}
	return doc, nil
}

func (s *Store) save(doc document) error {
	doc.SchemaVersion = "1"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".triage-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err == nil {
		return nil
	}
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(name, s.path)
}

func decisionKey(decision Decision) string {
	if decision.Fingerprint == "" {
		return strings.ToLower(decision.OccurrenceID)
	}
	target := filepath.Clean(decision.Target)
	if runtime.GOOS == "windows" {
		target = strings.ToLower(target)
	}
	sum := sha256.Sum256([]byte(target + "\n" + decision.Fingerprint))
	return fmt.Sprintf("%x", sum[:])
}
