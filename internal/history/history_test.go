package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"security-scanner/internal/output"
	"security-scanner/internal/scan"
	"security-scanner/internal/triage"
)

func TestLoadPostScanDiscoversOptionalFixedArtifact(t *testing.T) {
	out := filepath.Join(t.TempDir(), "scan")
	guard, err := output.PreparePrivateDir(out)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{ScanID: "scan-advisory", OutputDir: out}
	if _, ok, err := LoadPostScan(record); err != nil || ok {
		t.Fatalf("missing advisory = %t, %v", ok, err)
	}
	if err := output.WritePrivateFileAtomic(guard, "post-scan.json", []byte(`{"summary":"next"}`)); err != nil {
		t.Fatal(err)
	}
	data, ok, err := LoadPostScan(record)
	if err != nil || !ok || !strings.Contains(string(data), "next") {
		t.Fatalf("advisory = %s, %t, %v", data, ok, err)
	}
	if err := os.WriteFile(filepath.Join(out, "post-scan.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPostScan(record); err == nil {
		t.Fatal("corrupt advisory was accepted")
	}
}

func TestStoreAddListAndGet(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "history", "index.json"))
	result := &scan.Result{OutDir: filepath.Join(t.TempDir(), "scan"), Manifest: scan.ScanManifest{
		ScanID: "scan-1", Target: filepath.Join(t.TempDir(), "repo"), Status: "completed",
		Provider: "test", Model: "model", StartedAt: time.Unix(10, 0), CompletedAt: time.Unix(20, 0),
		LaunchConfig: &scan.LaunchConfiguration{AuthMode: "env", MaxIterations: 17, Excludes: []string{"vendor"}},
	}}
	if err := store.Add(result); err != nil {
		t.Fatal(err)
	}
	records, err := store.List(result.Manifest.Target)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ScanID != "scan-1" {
		t.Fatalf("unexpected records: %#v", records)
	}
	record, err := store.Get("scan-1")
	if err != nil || record.OutputDir != result.OutDir {
		t.Fatalf("record = %#v, err = %v", record, err)
	}
	if record.LaunchConfig == nil || record.LaunchConfig.AuthMode != "env" || record.LaunchConfig.MaxIterations != 17 {
		t.Fatalf("launch configuration was not persisted: %#v", record.LaunchConfig)
	}
}

func TestStoreReplacesDuplicateScanID(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "index.json"))
	result := &scan.Result{Manifest: scan.ScanManifest{ScanID: "same", Target: t.TempDir(), StartedAt: time.Now()}}
	if err := store.Add(result); err != nil {
		t.Fatal(err)
	}
	result.Manifest.Status = "completed"
	if err := store.Add(result); err != nil {
		t.Fatal(err)
	}
	records, err := store.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Status != "completed" {
		t.Fatalf("unexpected records: %#v", records)
	}
}

func TestStoreGetResolvesUniqueScanIDPrefix(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "index.json"))
	for _, scanID := range []string{"scan-alpha-1111", "scan-alpha-2222", "scan-beta-3333"} {
		if err := store.Add(&scan.Result{Manifest: scan.ScanManifest{ScanID: scanID, Target: t.TempDir(), StartedAt: time.Now()}}); err != nil {
			t.Fatal(err)
		}
	}
	for input, want := range map[string]string{
		"scan-alpha-1111": "scan-alpha-1111",
		"scan-alpha-1":    "scan-alpha-1111",
		" scan-beta ":     "scan-beta-3333",
	} {
		record, err := store.Get(input)
		if err != nil || record.ScanID != want {
			t.Errorf("Get(%q) = %#v, %v; want %q", input, record, err, want)
		}
	}
	if _, err := store.Get("scan-alpha"); err == nil || !strings.Contains(err.Error(), "ambiguous") || !strings.Contains(err.Error(), "scan-alpha-1111") || !strings.Contains(err.Error(), "scan-alpha-2222") {
		t.Fatalf("unexpected ambiguous-prefix error: %v", err)
	}
	if _, err := store.Get(""); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("unexpected empty-ID error: %v", err)
	}
	if _, err := store.Get("scan-missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected missing-prefix error: %v", err)
	}
}

func TestRepositoryFindingsTracksLatestAndDismissedIdentities(t *testing.T) {
	target := t.TempDir()
	records := []Record{
		{ScanID: "scan-latest", Target: target, StartedAt: time.Unix(30, 0)},
		{ScanID: "scan-old", Target: target, StartedAt: time.Unix(10, 0)},
		{ScanID: "scan-middle", Target: target, StartedAt: time.Unix(20, 0)},
	}
	results := map[string]*scan.Result{
		"scan-old": {Findings: scan.FindingsDocument{Findings: []scan.Finding{
			{ID: "F-OLD-CONFIRMED", Fingerprint: "confirmed", Title: "Confirmed issue", Severity: scan.SeverityHigh},
			{ID: "F-OLD-HISTORICAL", Fingerprint: "historical", Title: "Historical issue", Severity: scan.SeverityMedium},
			{ID: "F-OLD-DISMISSED", Fingerprint: "dismissed", Title: "Dismissed issue", Severity: scan.SeverityCritical},
		}}},
		"scan-middle": {Findings: scan.FindingsDocument{Findings: []scan.Finding{
			{ID: "F-MIDDLE-HISTORICAL", Fingerprint: "historical", Title: "Historical issue", Severity: scan.SeverityMedium},
		}}},
		"scan-latest": {Findings: scan.FindingsDocument{Findings: []scan.Finding{
			{ID: "F-LATEST-CONFIRMED", Fingerprint: "confirmed", Title: "Confirmed issue", Severity: scan.SeverityHigh},
		}}},
	}
	decisions := []triage.Decision{{
		OccurrenceID: "scan-old:F-OLD-DISMISSED", Fingerprint: "dismissed", Target: target, Disposition: "false_positive",
	}}
	findings, err := repositoryFindings(records, decisions, func(record Record) (*scan.Result, error) {
		return results[record.ScanID], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %#v", findings)
	}
	confirmed, historical := findings[0], findings[1]
	if confirmed.Fingerprint != "confirmed" || !confirmed.ConfirmedInLatestScan || confirmed.OccurrenceCount != 2 || confirmed.ScanID != "scan-latest" {
		t.Fatalf("confirmed finding = %#v", confirmed)
	}
	if historical.Fingerprint != "historical" || historical.ConfirmedInLatestScan || historical.OccurrenceCount != 2 || historical.ScanID != "scan-middle" {
		t.Fatalf("historical finding = %#v", historical)
	}
	if !historical.KnownSince.Equal(time.Unix(10, 0)) || len(historical.KnownScanIDs) != 2 || historical.KnownScanIDs[0] != "scan-old" || historical.KnownScanIDs[1] != "scan-middle" {
		t.Fatalf("historical identity metadata = %#v", historical)
	}
}

func TestLoadLogsReadsPrivateJSONLEvents(t *testing.T) {
	out := filepath.Join(t.TempDir(), "scan")
	guard, err := output.PreparePrivateDir(out)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("{\"timestamp\":\"1970-01-01T00:01:40Z\",\"event\":\"scan.started\"}\n{\"timestamp\":\"1970-01-01T00:01:41Z\",\"event\":\"scan.completed\",\"message\":\"completed\"}\n")
	if err := output.WritePrivateFileAtomic(guard, "scan-log.jsonl", data); err != nil {
		t.Fatal(err)
	}
	log, err := LoadLogs(Record{ScanID: "scan-1", OutputDir: out})
	if err != nil {
		t.Fatal(err)
	}
	if log.ScanID != "scan-1" || len(log.Events) != 2 || log.Events[1].Event != "scan.completed" {
		t.Fatalf("unexpected scan log: %#v", log)
	}
	oldOut := filepath.Join(t.TempDir(), "old-scan")
	if _, err := output.PreparePrivateDir(oldOut); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLogs(Record{ScanID: "scan-old", OutputDir: oldOut}); err == nil || !strings.Contains(err.Error(), "no saved activity log") {
		t.Fatalf("unexpected missing-log error: %v", err)
	}
}

func TestLoadResultExplainsMissingSavedArtifacts(t *testing.T) {
	missingOutput := filepath.Join(t.TempDir(), "missing-scan")
	if _, err := LoadResult(Record{ScanID: "scan-missing-output", OutputDir: missingOutput}); err == nil || !strings.Contains(err.Error(), "output directory is unavailable") || !strings.Contains(err.Error(), "moved or deleted") {
		t.Fatalf("unexpected missing-output error: %v", err)
	}
	out := filepath.Join(t.TempDir(), "incomplete-scan")
	if _, err := output.PreparePrivateDir(out); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResult(Record{ScanID: "scan-missing-artifact", OutputDir: out}); err == nil || !strings.Contains(err.Error(), "missing required artifact scan-manifest.json") || !strings.Contains(err.Error(), "incomplete or damaged") {
		t.Fatalf("unexpected missing-artifact error: %v", err)
	}
}

func TestLoadResultRejectsArtifactChangedAfterSealing(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory, err := scan.BuildInventory(target, scan.InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Unix(300, 0)
	result, err := scan.Finalize(inventory, nil, scan.Submission{ThreatModel: "Untrusted callers."}, scan.FinalizeOptions{
		ScanID: scan.AllocateScanID(target, started), OutputDir: filepath.Join(t.TempDir(), "scan"),
		Provider: "test", Model: "test", StartedAt: started,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := Record{
		ScanID: result.Manifest.ScanID, Target: target, OutputDir: result.OutDir,
		Status: result.Manifest.Status,
	}
	if _, err := LoadResult(record); err != nil {
		t.Fatalf("sealed result was rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(result.OutDir, "scan-log.jsonl"), []byte("{\"event\":\"post_scan.completed\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResult(record); err != nil {
		t.Fatalf("operational activity journal invalidated canonical seal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(result.OutDir, "findings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResult(record); err == nil || !strings.Contains(err.Error(), "does not match its sealed digest") {
		t.Fatalf("modified artifact error = %v", err)
	}
}
