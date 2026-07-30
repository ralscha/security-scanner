package triage

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestSetFalsePositivePersistsAndUpdates(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "triage.json"))
	decision := Decision{OccurrenceID: "F-ABC", Fingerprint: "abc", ScanID: "scan-1", Target: t.TempDir(), Reason: "not reachable"}
	if err := store.SetDecision(decision); err != nil {
		t.Fatal(err)
	}
	decision.Reason = "protected by authorization"
	if err := store.SetDecision(decision); err != nil {
		t.Fatal(err)
	}
	decisions, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || decisions[0].Reason != "protected by authorization" {
		t.Fatalf("unexpected decisions: %#v", decisions)
	}
}

func TestCaseDistinctTargetsKeepSeparateDecisions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows paths are case-insensitive")
	}
	store := NewStore(filepath.Join(t.TempDir(), "triage.json"))
	parent := t.TempDir()
	for _, target := range []string{filepath.Join(parent, "Repo"), filepath.Join(parent, "repo")} {
		decision := Decision{OccurrenceID: "scan-1:F-ABC", Fingerprint: "abc", ScanID: "scan-1", Target: target, Reason: "not reachable"}
		if err := store.SetDecision(decision); err != nil {
			t.Fatal(err)
		}
	}
	decisions, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 2 {
		t.Fatalf("case-distinct target decisions collapsed: %#v", decisions)
	}
}

func TestSetFalsePositiveRequiresReason(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "triage.json"))
	decision := Decision{OccurrenceID: "F-ABC", Fingerprint: "abc", ScanID: "scan-1", Target: t.TempDir(), Reason: " "}
	if err := store.SetDecision(decision); err == nil {
		t.Fatal("expected reason validation error")
	}
}
