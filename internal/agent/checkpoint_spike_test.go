package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"security-scanner/internal/output"
)

// spikeCheckpointStore deliberately remains test-only. ADR 0002 records why
// the scanner does not expose production checkpoint resume with Eino v0.9.13.
type spikeCheckpointStore struct {
	guard   *output.Guard
	maxSize int
}

func (s *spikeCheckpointStore) Get(_ context.Context, checkpointID string) ([]byte, bool, error) {
	data, err := output.ReadPrivateFile(s.guard, spikeCheckpointName(checkpointID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(data) > s.maxSize {
		return nil, false, fmt.Errorf("checkpoint exceeds maximum size %d bytes", s.maxSize)
	}
	return data, true, nil
}

func (s *spikeCheckpointStore) Set(_ context.Context, checkpointID string, checkpoint []byte) error {
	if len(checkpoint) > s.maxSize {
		return fmt.Errorf("checkpoint exceeds maximum size %d bytes", s.maxSize)
	}
	return output.WritePrivateFileAtomic(s.guard, spikeCheckpointName(checkpointID), append([]byte(nil), checkpoint...))
}

func spikeCheckpointName(checkpointID string) string {
	digest := sha256.Sum256([]byte(checkpointID))
	return fmt.Sprintf("%x.checkpoint", digest[:])
}

func TestCheckpointSpikeStoreSurvivesFreshStoreAndHashesArbitraryKeys(t *testing.T) {
	guard, err := output.PreparePrivateDir(filepath.Join(t.TempDir(), ".recovery", "checkpoints"))
	if err != nil {
		t.Fatal(err)
	}
	first := &spikeCheckpointStore{guard: guard, maxSize: 1024}
	key := `../../unsafe\checkpoint:key`
	payload := []byte("opaque eino checkpoint bytes")
	if err := first.Set(context.Background(), key, payload); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(guard.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != spikeCheckpointName(key) {
		t.Fatalf("checkpoint key was not mapped to one safe hashed basename: %#v", entries)
	}

	// A new store instance represents a fresh process opening the same private
	// directory; no in-memory state is used to recover the opaque bytes.
	second := &spikeCheckpointStore{guard: guard, maxSize: 1024}
	got, ok, err := second.Get(context.Background(), key)
	if err != nil || !ok || string(got) != string(payload) {
		t.Fatalf("fresh-store Get = %q, %t, %v", got, ok, err)
	}
	if err := second.Set(context.Background(), "oversized", make([]byte, 1025)); err == nil {
		t.Fatal("oversized checkpoint was accepted")
	}
}
