package history

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"security-scanner/internal/output"
	"security-scanner/internal/scan"
	"security-scanner/internal/triage"
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
	ErrorClass   string                    `json:"error_class,omitempty"`
}

type Index struct {
	SchemaVersion string   `json:"schema_version"`
	Scans         []Record `json:"scans"`
}

type RepositoryFinding struct {
	scan.Finding
	OccurrenceID          string    `json:"occurrence_id"`
	ScanID                string    `json:"scan_id"`
	Target                string    `json:"target"`
	Status                string    `json:"status"`
	ConfirmedInLatestScan bool      `json:"confirmed_in_latest_scan"`
	KnownSince            time.Time `json:"known_since"`
	KnownScanIDs          []string  `json:"known_scan_ids"`
	OccurrenceCount       int       `json:"occurrence_count"`
}

type ScanLog struct {
	ScanID string               `json:"scan_id"`
	Events []scan.ActivityEvent `json:"events"`
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
	record := Record{
		ScanID: result.Manifest.ScanID, Target: result.Manifest.Target, OutputDir: result.OutDir,
		Status: result.Manifest.Status, Provider: result.Manifest.Provider, Model: result.Manifest.Model,
		StartedAt: result.Manifest.StartedAt, CompletedAt: result.Manifest.CompletedAt,
		FindingCount: result.Manifest.FindingCount, TargetMode: result.Manifest.TargetMode,
		TargetRef: result.Manifest.TargetRef, TargetPaths: append([]string(nil), result.Manifest.TargetPaths...),
		LaunchConfig: cloneLaunchConfiguration(result.Manifest.LaunchConfig),
	}
	return s.Upsert(record)
}

// Upsert registers an in-progress or failed session, or updates it with a
// canonical result once finalization succeeds.
func (s *Store) Upsert(record Record) error {
	if strings.TrimSpace(record.ScanID) == "" || strings.TrimSpace(record.Target) == "" {
		return fmt.Errorf("history record scan ID and target are required")
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	index, err := s.load()
	if err != nil {
		return err
	}
	record.TargetPaths = append([]string(nil), record.TargetPaths...)
	record.LaunchConfig = cloneLaunchConfiguration(record.LaunchConfig)
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
	clone.KnowledgeBasePaths = append([]string(nil), config.KnowledgeBasePaths...)
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
	scanID = strings.TrimSpace(scanID)
	if scanID == "" {
		return Record{}, fmt.Errorf("scan ID is required")
	}
	records, err := s.List("")
	if err != nil {
		return Record{}, err
	}
	for _, record := range records {
		if record.ScanID == scanID {
			return record, nil
		}
	}
	matches := make([]Record, 0, 1)
	for _, record := range records {
		if strings.HasPrefix(record.ScanID, scanID) {
			matches = append(matches, record)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		ids := make([]string, len(matches))
		for index, match := range matches {
			ids[index] = match.ScanID
		}
		sort.Strings(ids)
		return Record{}, fmt.Errorf("scan ID prefix %q is ambiguous; matches: %s", scanID, strings.Join(ids, ", "))
	}
	return Record{}, fmt.Errorf("scan %q was not found", scanID)
}

func (s *Store) RepositoryFindings(target string, decisions []triage.Decision) ([]RepositoryFinding, error) {
	records, err := s.List(target)
	if err != nil {
		return nil, err
	}
	return repositoryFindings(records, decisions, LoadResult)
}

func repositoryFindings(records []Record, decisions []triage.Decision, load func(Record) (*scan.Result, error)) ([]RepositoryFinding, error) {
	completed := make([]Record, 0, len(records))
	for _, record := range records {
		if record.Status == "" || record.Status == "completed" || record.Status == "completed_with_gaps" {
			completed = append(completed, record)
		}
	}
	if len(completed) == 0 {
		return []RepositoryFinding{}, nil
	}
	ordered := append([]Record(nil), completed...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].StartedAt.Equal(ordered[j].StartedAt) {
			return ordered[i].ScanID < ordered[j].ScanID
		}
		return ordered[i].StartedAt.Before(ordered[j].StartedAt)
	})
	latestScanID := ordered[len(ordered)-1].ScanID
	byIdentity := make(map[string]*RepositoryFinding)
	identityByOccurrence := make(map[string]string)
	for _, record := range ordered {
		result, err := load(record)
		if err != nil {
			return nil, err
		}
		for _, finding := range result.Findings.Findings {
			identity := finding.Fingerprint
			if identity == "" {
				identity = record.ScanID + "\x00" + finding.ID
			}
			occurrenceID := record.ScanID + ":" + finding.ID
			current, ok := byIdentity[identity]
			if !ok {
				current = &RepositoryFinding{KnownSince: record.StartedAt, Status: "open", Target: record.Target}
				byIdentity[identity] = current
			}
			current.Finding = finding
			current.OccurrenceID = occurrenceID
			current.ScanID = record.ScanID
			current.ConfirmedInLatestScan = record.ScanID == latestScanID
			current.KnownScanIDs = append(current.KnownScanIDs, record.ScanID)
			current.OccurrenceCount++
			identityByOccurrence[occurrenceID] = identity
		}
	}
	dismissed := make(map[string]struct{})
	for _, decision := range decisions {
		if decision.Disposition != "false_positive" {
			continue
		}
		if identity, ok := identityByOccurrence[decision.OccurrenceID]; ok {
			dismissed[identity] = struct{}{}
		}
		if decision.Fingerprint == "" {
			continue
		}
		for identity, finding := range byIdentity {
			if identity == decision.Fingerprint && samePath(finding.Target, decision.Target) {
				dismissed[identity] = struct{}{}
			}
		}
	}
	findings := make([]RepositoryFinding, 0, len(byIdentity)-len(dismissed))
	for identity, finding := range byIdentity {
		if _, ok := dismissed[identity]; !ok {
			findings = append(findings, *finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ConfirmedInLatestScan != findings[j].ConfirmedInLatestScan {
			return findings[i].ConfirmedInLatestScan
		}
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		if findings[i].Title != findings[j].Title {
			return findings[i].Title < findings[j].Title
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	return findings, nil
}

func severityRank(severity scan.Severity) int {
	return map[scan.Severity]int{
		scan.SeverityCritical: 5,
		scan.SeverityHigh:     4,
		scan.SeverityMedium:   3,
		scan.SeverityLow:      2,
		scan.SeverityInfo:     1,
	}[severity]
}

func (s *Store) load() (Index, error) {
	guard, err := output.EnsurePrivateDir(filepath.Dir(s.path))
	if err != nil {
		return Index{}, fmt.Errorf("prepare private history directory: %w", err)
	}
	data, err := output.ReadPrivateFile(guard, filepath.Base(s.path))
	if errors.Is(err, os.ErrNotExist) {
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
	if _, statErr := os.Lstat(record.OutputDir); os.IsNotExist(statErr) {
		return nil, fmt.Errorf("saved scan %s output directory is unavailable; it may have been moved or deleted: %s", record.ScanID, record.OutputDir)
	}
	guard, err := output.OpenPrivateDir(record.OutputDir)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("saved scan %s output directory is unavailable; it may have been moved or deleted: %s", record.ScanID, record.OutputDir)
	}
	if err != nil {
		return nil, fmt.Errorf("validate private output for scan %s: %w", record.ScanID, err)
	}
	result.OutDir = guard.Path()
	readRequired := func(name string) ([]byte, error) {
		data, err := output.ReadPrivateFile(guard, name)
		if err != nil {
			_, statErr := os.Lstat(filepath.Join(guard.Path(), name))
			if errors.Is(err, os.ErrNotExist) || os.IsNotExist(statErr) {
				return nil, fmt.Errorf("saved scan %s is missing required artifact %s; its output may be incomplete or damaged", record.ScanID, name)
			}
			return nil, fmt.Errorf("read %s for scan %s: %w", name, record.ScanID, err)
		}
		return data, nil
	}
	manifestData, err := readRequired("scan-manifest.json")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(manifestData, &result.Manifest); err != nil {
		return nil, fmt.Errorf("decode scan-manifest.json for scan %s: %w", record.ScanID, err)
	}
	if result.Manifest.SchemaVersion != scan.SchemaVersion {
		return nil, fmt.Errorf("saved scan %s uses unsupported schema version %q", record.ScanID, result.Manifest.SchemaVersion)
	}
	if result.Manifest.ScanID != record.ScanID {
		return nil, fmt.Errorf("saved scan %s manifest has mismatched scan ID %q", record.ScanID, result.Manifest.ScanID)
	}
	if record.Status != "" && result.Manifest.Status != record.Status {
		return nil, fmt.Errorf("saved scan %s manifest status differs from scan history", record.ScanID)
	}
	if record.Target != "" && !samePath(record.Target, result.Manifest.Target) {
		return nil, fmt.Errorf("saved scan %s manifest target differs from scan history", record.ScanID)
	}
	requiredArtifacts := map[string]string{
		"findings": "findings.json", "coverage": "coverage.json", "report": "report.md",
		"sarif": "results.sarif", "log": "scan-log.jsonl",
	}
	for logical, name := range requiredArtifacts {
		if result.Manifest.Artifacts[logical] != name {
			return nil, fmt.Errorf("saved scan %s manifest does not declare required artifact %s", record.ScanID, name)
		}
	}
	sealed := make(map[string][]byte, len(requiredArtifacts))
	seenNames := make(map[string]struct{}, len(result.Manifest.Artifacts))
	for _, name := range result.Manifest.Artifacts {
		if filepath.Base(name) != name || name == "." || name == "" {
			return nil, fmt.Errorf("saved scan %s manifest contains an unsafe artifact path", record.ScanID)
		}
		if _, duplicate := seenNames[name]; duplicate {
			return nil, fmt.Errorf("saved scan %s manifest contains a duplicate artifact path", record.ScanID)
		}
		seenNames[name] = struct{}{}
		data, readErr := readRequired(name)
		if readErr != nil {
			return nil, readErr
		}
		if name != "scan-log.jsonl" {
			expected := result.Manifest.ArtifactDigests[name]
			digest := sha256.Sum256(data)
			actual := fmt.Sprintf("sha256:%x", digest[:])
			if expected == "" || expected != actual {
				return nil, fmt.Errorf("saved scan %s artifact %s does not match its sealed digest", record.ScanID, name)
			}
		}
		sealed[name] = data
	}
	for _, artifact := range []struct {
		name        string
		destination any
	}{
		{name: "findings.json", destination: &result.Findings},
		{name: "coverage.json", destination: &result.Coverage},
	} {
		if err := json.Unmarshal(sealed[artifact.name], artifact.destination); err != nil {
			return nil, fmt.Errorf("decode %s for scan %s: %w", artifact.name, record.ScanID, err)
		}
	}
	if result.Findings.SchemaVersion != scan.SchemaVersion || result.Coverage.SchemaVersion != scan.SchemaVersion || result.Findings.ScanID != record.ScanID || result.Coverage.ScanID != record.ScanID {
		return nil, fmt.Errorf("saved scan %s canonical artifact identities do not match its manifest", record.ScanID)
	}
	if len(result.Findings.Findings) != result.Manifest.FindingCount {
		return nil, fmt.Errorf("saved scan %s canonical finding count does not match its manifest", record.ScanID)
	}
	if data, err := output.ReadPrivateFile(guard, "post-scan.json"); err == nil {
		var advisory json.RawMessage
		if err := json.Unmarshal(data, &advisory); err != nil {
			return nil, fmt.Errorf("decode post-scan.json for scan %s: %w", record.ScanID, err)
		}
		result.PostScan = advisory
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read post-scan.json for scan %s: %w", record.ScanID, err)
	}
	return result, nil
}

func LoadLogs(record Record) (ScanLog, error) {
	guard, err := output.OpenPrivateDir(record.OutputDir)
	if err != nil {
		return ScanLog{}, fmt.Errorf("validate private output for scan %s: %w", record.ScanID, err)
	}
	data, err := output.ReadPrivateFile(guard, "scan-log.jsonl")
	if os.IsNotExist(err) {
		return ScanLog{}, fmt.Errorf("no saved activity log is available for scan %s", record.ScanID)
	}
	if err != nil {
		return ScanLog{}, fmt.Errorf("read activity log for scan %s: %w", record.ScanID, err)
	}
	log := ScanLog{ScanID: record.ScanID, Events: []scan.ActivityEvent{}}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var event scan.ActivityEvent
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			return ScanLog{}, fmt.Errorf("decode activity log for scan %s: %w", record.ScanID, err)
		}
		log.Events = append(log.Events, event)
	}
	return log, nil
}

// LoadPostScan discovers the optional advisory artifact by its fixed filename;
// it is deliberately not part of the canonical scan manifest.
func LoadPostScan(record Record) (json.RawMessage, bool, error) {
	guard, err := output.OpenPrivateDir(record.OutputDir)
	if err != nil {
		return nil, false, fmt.Errorf("validate private output for scan %s: %w", record.ScanID, err)
	}
	data, err := output.ReadPrivateFile(guard, "post-scan.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read post-scan advisory for scan %s: %w", record.ScanID, err)
	}
	var value json.RawMessage
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, false, fmt.Errorf("decode post-scan advisory for scan %s: %w", record.ScanID, err)
	}
	return value, true, nil
}
