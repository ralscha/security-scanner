package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"security-scanner/internal/output"
	"security-scanner/internal/scan"
)

const schemaVersion = "1"

type Record struct {
	ScanID       string                    `json:"scan_id"`
	Target       string                    `json:"target"`
	OutputDir    string                    `json:"output_dir"`
	Status       string                    `json:"status"`
	Provider     string                    `json:"provider"`
	Model        string                    `json:"model"`
	StartedAt    time.Time                 `json:"started_at"`
	CompletedAt  time.Time                 `json:"completed_at"`
	FindingCount int                       `json:"finding_count"`
	TargetMode   string                    `json:"target_mode,omitempty"`
	TargetRef    string                    `json:"target_ref,omitempty"`
	TargetPaths  []string                  `json:"target_paths,omitempty"`
	LaunchConfig *scan.LaunchConfiguration `json:"launch_configuration,omitempty"`
}

type Index struct {
	SchemaVersion string   `json:"schema_version"`
	Scans         []Record `json:"scans"`
}

type Store struct {
	path string
}

var storeMu sync.Mutex

func DefaultStore() (*Store, error) {
	state, err := output.StateDir()
	if err != nil {
		return nil, err
	}
	return NewStore(filepath.Join(state, "history", "index.json")), nil
}

func NewStore(path string) *Store { return &Store{path: path} }

func (s *Store) Add(result *scan.Result) error {
	if result == nil {
		return fmt.Errorf("scan result is required")
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	index, err := s.load()
	if err != nil {
		return err
	}
	record := Record{
		ScanID: result.Manifest.ScanID, Target: result.Manifest.Target, OutputDir: result.OutDir,
		Status: result.Manifest.Status, Provider: result.Manifest.Provider, Model: result.Manifest.Model,
		StartedAt: result.Manifest.StartedAt, CompletedAt: result.Manifest.CompletedAt,
		FindingCount: result.Manifest.FindingCount, TargetMode: result.Manifest.TargetMode,
		TargetRef: result.Manifest.TargetRef, TargetPaths: append([]string(nil), result.Manifest.TargetPaths...),
		LaunchConfig: cloneLaunchConfiguration(result.Manifest.LaunchConfig),
	}
	replaced := false
	for i := range index.Scans {
		if index.Scans[i].ScanID == record.ScanID {
			index.Scans[i] = record
			replaced = true
			break
		}
	}
	if !replaced {
		index.Scans = append(index.Scans, record)
	}
	sort.Slice(index.Scans, func(i, j int) bool { return index.Scans[i].StartedAt.After(index.Scans[j].StartedAt) })
	return s.save(index)
}

func cloneLaunchConfiguration(config *scan.LaunchConfiguration) *scan.LaunchConfiguration {
	if config == nil {
		return nil
	}
	clone := *config
	clone.Excludes = append([]string(nil), config.Excludes...)
	return &clone
}

func (s *Store) List(target string) ([]Record, error) {
	storeMu.Lock()
	defer storeMu.Unlock()
	index, err := s.load()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(target) == "" {
		return append([]Record(nil), index.Scans...), nil
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("resolve history target: %w", err)
	}
	result := make([]Record, 0)
	for _, record := range index.Scans {
		if samePath(record.Target, absTarget) {
			result = append(result, record)
		}
	}
	return result, nil
}

func (s *Store) Get(scanID string) (Record, error) {
	records, err := s.List("")
	if err != nil {
		return Record{}, err
	}
	for _, record := range records {
		if record.ScanID == scanID {
			return record, nil
		}
	}
	return Record{}, fmt.Errorf("scan %q was not found", scanID)
}

func (s *Store) load() (Index, error) {
	guard, err := output.EnsurePrivateDir(filepath.Dir(s.path))
	if err != nil {
		return Index{}, fmt.Errorf("prepare private history directory: %w", err)
	}
	data, err := output.ReadPrivateFile(guard, filepath.Base(s.path))
	if os.IsNotExist(err) {
		return Index{SchemaVersion: schemaVersion, Scans: []Record{}}, nil
	}
	if err != nil {
		return Index{}, fmt.Errorf("read history index: %w", err)
	}
	var index Index
	if err := json.Unmarshal(data, &index); err != nil {
		return Index{}, fmt.Errorf("decode history index: %w", err)
	}
	if index.Scans == nil {
		index.Scans = []Record{}
	}
	return index, nil
}

func (s *Store) save(index Index) error {
	index.SchemaVersion = schemaVersion
	guard, err := output.EnsurePrivateDir(filepath.Dir(s.path))
	if err != nil {
		return fmt.Errorf("prepare private history directory: %w", err)
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("encode history index: %w", err)
	}
	data = append(data, '\n')
	return output.WritePrivateFileAtomic(guard, filepath.Base(s.path), data)
}

func samePath(left, right string) bool {
	rel, err := filepath.Rel(filepath.Clean(left), filepath.Clean(right))
	return err == nil && rel == "."
}

func LoadResult(record Record) (*scan.Result, error) {
	result := &scan.Result{OutDir: record.OutputDir}
	guard, err := output.OpenPrivateDir(record.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("validate private output for scan %s: %w", record.ScanID, err)
	}
	result.OutDir = guard.Path()
	for name, destination := range map[string]any{
		"scan-manifest.json": &result.Manifest,
		"findings.json":      &result.Findings,
		"coverage.json":      &result.Coverage,
	} {
		data, err := output.ReadPrivateFile(guard, name)
		if err != nil {
			return nil, fmt.Errorf("read %s for scan %s: %w", name, record.ScanID, err)
		}
		if err := json.Unmarshal(data, destination); err != nil {
			return nil, fmt.Errorf("decode %s for scan %s: %w", name, record.ScanID, err)
		}
	}
	return result, nil
}
