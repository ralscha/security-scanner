package runstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"security-scanner/internal/output"
	"security-scanner/internal/scan"
)

func TestStoreTransitionsAttemptsAndTerminalReplay(t *testing.T) {
	guard, err := output.PreparePrivateDir(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	scanID := scan.AllocateScanID(t.TempDir(), time.Unix(100, 0))
	store, err := Create(guard, Session{ScanID: scanID, Target: t.TempDir(), OutputDir: guard.Path(), StartedAt: time.Unix(100, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(StatusAnalyzing); err != nil {
		t.Fatal(err)
	}
	if err := store.StartAttempt(1); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishAttempt(1, "succeeded", "", false); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(StatusFinalizing); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(StatusCompleted); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(StatusCompleted); err != nil {
		t.Fatalf("exact terminal replay failed: %v", err)
	}
	if err := store.Transition(StatusFailed); err == nil {
		t.Fatal("terminal success was reversed")
	}
	if err := store.Fail("internal", "late error", false); err == nil {
		t.Fatal("late failure replaced terminal success")
	}
	opened, err := Open(guard)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Snapshot().Status != StatusCompleted || len(opened.Snapshot().Attempts) != 1 {
		t.Fatalf("unexpected persisted state: %#v", opened.Snapshot())
	}
}

func TestStorePersistsRedactedFailureAndJournal(t *testing.T) {
	guard, err := output.PreparePrivateDir(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	scanID := scan.AllocateScanID(t.TempDir(), time.Unix(200, 0))
	store, err := Create(guard, Session{ScanID: scanID, Target: t.TempDir(), OutputDir: guard.Path(), StartedAt: time.Unix(200, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Fail("authentication", "Authorization: Bearer synthetic-secret", false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(guard.Path(), StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "synthetic-secret") || !strings.Contains(string(data), "[redacted]") {
		t.Fatalf("failure was not redacted: %s", data)
	}
	journal, err := NewJournal(guard, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Record(scan.ActivityEvent{Timestamp: time.Now(), Event: "analysis.attempt.failed", ScanID: scanID, Message: "api_key=synthetic-secret"}); err != nil {
		t.Fatal(err)
	}
	logData, err := os.ReadFile(filepath.Join(guard.Path(), JournalFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logData), "synthetic-secret") || !strings.Contains(string(logData), "[redacted]") {
		t.Fatalf("journal was not redacted: %s", logData)
	}
	var event scan.ActivityEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(logData))), &event); err != nil || event.ScanID != scanID {
		t.Fatalf("invalid journal event: %#v, %v", event, err)
	}
}
