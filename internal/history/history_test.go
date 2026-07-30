package history

import (
	"path/filepath"
	"testing"
	"time"

	"security-scanner/internal/scan"
)

func TestStoreAddListAndGet(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "history", "index.json"))
	result := &scan.Result{OutDir: filepath.Join(t.TempDir(), "scan"), Manifest: scan.ScanManifest{
		ScanID: "scan-1", Target: filepath.Join(t.TempDir(), "repo"), Status: "completed",
		Provider: "test", Model: "model", StartedAt: time.Unix(10, 0), CompletedAt: time.Unix(20, 0),
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
