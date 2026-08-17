package publication

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"security-scanner/internal/history"
	linearapi "security-scanner/internal/linear"
	"security-scanner/internal/output"
	"security-scanner/internal/redact"
	"security-scanner/internal/scan"
)

const batchSize = 20

type Client interface {
	CreateIssue(context.Context, linearapi.CreateIssueInput) (linearapi.Issue, error)
	ResolveUser(context.Context, string) (string, error)
}

type PublishedIssue struct {
	FindingID       string `json:"finding_id"`
	OccurrenceID    string `json:"occurrence_id"`
	IssueIdentifier string `json:"issue_identifier"`
	URL             string `json:"url,omitempty"`
}

type FailedIssue struct {
	FindingID string `json:"finding_id"`
	Error     string `json:"error"`
}

type Counts struct {
	Findings int `json:"findings"`
	Created  int `json:"created"`
	Failed   int `json:"failed"`
}

type Result struct {
	ScanID      string           `json:"scan_id"`
	UploadID    string           `json:"upload_id"`
	Destination Destination      `json:"destination"`
	Created     []PublishedIssue `json:"created"`
	Failed      []FailedIssue    `json:"failed"`
	Counts      Counts           `json:"counts"`
	DryRun      bool             `json:"dry_run,omitempty"`
	Issues      []PreparedIssue  `json:"issues,omitempty"`
	Warnings    []string         `json:"warnings,omitempty"`
	ReceiptPath string           `json:"receipt_path,omitempty"`
}

type Progress struct {
	Type            string `json:"type"`
	ScanID          string `json:"scan_id,omitempty"`
	FindingID       string `json:"finding_id,omitempty"`
	IssueIdentifier string `json:"issue_identifier,omitempty"`
	Error           string `json:"error,omitempty"`
	Completed       int    `json:"completed,omitempty"`
	Total           int    `json:"total"`
	Created         int    `json:"created,omitempty"`
	Failed          int    `json:"failed,omitempty"`
}

type Options struct {
	TeamID     string
	ProjectID  string
	AssigneeID string
	DryRun     bool
	Client     Client
	StateDir   string
	Now        func() time.Time
	Progress   func(Progress)
}

func Publish(ctx context.Context, record history.Record, scanResult *scan.Result, options Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	prepared, err := Prepare(record, scanResult, options.TeamID, options.ProjectID, now().UTC())
	if err != nil {
		return Result{}, err
	}
	result := Result{
		ScanID: prepared.ScanID, UploadID: prepared.UploadID, Destination: prepared.Destination,
		Created: []PublishedIssue{}, Failed: []FailedIssue{}, Counts: Counts{Findings: len(prepared.Issues)},
	}
	if options.DryRun {
		result.DryRun = true
		result.Issues = prepared.Issues
		return result, nil
	}
	if len(prepared.Issues) == 0 {
		return result, nil
	}
	if options.Client == nil {
		return Result{}, fmt.Errorf("a Linear API key is required for publication")
	}
	assigneeID := strings.TrimSpace(options.AssigneeID)
	if strings.Contains(assigneeID, "@") {
		assigneeID, err = options.Client.ResolveUser(ctx, assigneeID)
		if err != nil {
			return Result{}, err
		}
	}
	stateDir := strings.TrimSpace(options.StateDir)
	if stateDir == "" {
		stateDir, err = output.StateDir()
		if err != nil {
			return Result{}, err
		}
	}
	handoff, err := newHandoff(stateDir, prepared, now().UTC())
	if err != nil {
		return Result{}, fmt.Errorf("prepare Linear publication handoff: %w", err)
	}
	report(options.Progress, Progress{Type: "started", ScanID: prepared.ScanID, Total: len(prepared.Issues)})

	completed := 0
	var progressMu sync.Mutex
	for start := 0; start < len(prepared.Issues) && ctx.Err() == nil; start += batchSize {
		end := start + batchSize
		if end > len(prepared.Issues) {
			end = len(prepared.Issues)
		}
		batch := prepared.Issues[start:end]
		outcomes := make([]publishOutcome, len(batch))
		var group sync.WaitGroup
		for index := range batch {
			group.Add(1)
			go func(index int) {
				defer group.Done()
				issue := batch[index]
				input := linearapi.CreateIssueInput{
					TeamID: prepared.Destination.TeamID, ProjectID: prepared.Destination.ProjectID,
					AssigneeID: assigneeID, Title: issue.Title, Description: issue.Description, Priority: issue.Priority,
				}
				created, createErr := options.Client.CreateIssue(ctx, input)
				outcome := publishOutcome{issue: issue, input: input}
				if createErr != nil {
					if ctx.Err() != nil {
						outcome.canceled = true
					} else {
						outcome.failure = redact.Text(createErr.Error())
					}
				} else {
					outcome.created = PublishedIssue{
						FindingID: issue.FindingID, OccurrenceID: issue.OccurrenceID,
						IssueIdentifier: created.Identifier, URL: created.URL,
					}
				}
				if !outcome.canceled {
					outcome.handoffErr = handoff.append(outcome)
				}
				outcomes[index] = outcome
				if outcome.canceled || outcome.handoffErr != nil {
					return
				}
				progressMu.Lock()
				completed++
				event := Progress{Type: "issue_completed", FindingID: issue.FindingID, Completed: completed, Total: len(prepared.Issues)}
				if outcome.failure != "" {
					event.Error = outcome.failure
				} else {
					event.IssueIdentifier = outcome.created.IssueIdentifier
				}
				report(options.Progress, event)
				progressMu.Unlock()
			}(index)
		}
		group.Wait()
		for _, outcome := range outcomes {
			if outcome.handoffErr != nil {
				return result, fmt.Errorf("could not preserve created Linear issues: %v; the publication handoff remains at %s; recover it before retrying to avoid creating duplicate issues", outcome.handoffErr, handoff.file)
			}
			if outcome.canceled {
				continue
			}
			if outcome.failure != "" {
				result.Failed = append(result.Failed, FailedIssue{FindingID: outcome.issue.FindingID, Error: outcome.failure})
			} else {
				result.Created = append(result.Created, outcome.created)
			}
		}
	}

	if ctx.Err() != nil {
		settled := make(map[string]struct{}, len(result.Created)+len(result.Failed))
		for _, issue := range result.Created {
			settled[issue.FindingID] = struct{}{}
		}
		for _, issue := range result.Failed {
			settled[issue.FindingID] = struct{}{}
		}
		for _, issue := range prepared.Issues {
			if _, ok := settled[issue.FindingID]; !ok {
				result.Failed = append(result.Failed, FailedIssue{FindingID: issue.FindingID, Error: "Linear API publication was interrupted before this finding could be created."})
			}
		}
		result.Counts.Created = len(result.Created)
		result.Counts.Failed = len(result.Failed)
		receiptPath, receiptErr := writeReceipt(stateDir, result, now().UTC())
		if receiptErr != nil {
			return result, fmt.Errorf("Linear publication was interrupted and its partial receipt could not be saved: %v; the publication handoff remains at %s; recover it before retrying to avoid creating duplicate issues: %w", receiptErr, handoff.file, ctx.Err())
		}
		result.ReceiptPath = receiptPath
		return result, fmt.Errorf("Linear publication was interrupted; the publication handoff remains at %s; recover it before retrying to avoid creating duplicate issues: %w", handoff.file, ctx.Err())
	}

	result.Counts.Created = len(result.Created)
	result.Counts.Failed = len(result.Failed)
	receiptPath, receiptErr := writeReceipt(stateDir, result, now().UTC())
	if receiptErr != nil {
		if len(result.Created) == 0 {
			return result, fmt.Errorf("save Linear publication receipt: %w", receiptErr)
		}
		result.Warnings = append(result.Warnings, redact.Text(fmt.Sprintf("Could not save the publication receipt: %v. Linear issues were already created; do not retry publication. Recovery data remains at %s.", receiptErr, handoff.file)))
	} else {
		result.ReceiptPath = receiptPath
		if cleanupErr := handoff.remove(); cleanupErr != nil {
			result.Warnings = append(result.Warnings, redact.Text(fmt.Sprintf("Could not remove the completed private publication handoff: %v", cleanupErr)))
		}
	}
	report(options.Progress, Progress{Type: "completed", Created: result.Counts.Created, Failed: result.Counts.Failed, Total: result.Counts.Findings})
	return result, nil
}

type publishOutcome struct {
	issue      PreparedIssue
	input      linearapi.CreateIssueInput
	created    PublishedIssue
	failure    string
	canceled   bool
	handoffErr error
}

type handoffRecord struct {
	ScanID          string         `json:"scan_id"`
	FindingID       string         `json:"finding_id"`
	OccurrenceID    string         `json:"occurrence_id"`
	IssueIdentifier string         `json:"issue_identifier,omitempty"`
	URL             string         `json:"url,omitempty"`
	Error           string         `json:"error,omitempty"`
	Arguments       map[string]any `json:"arguments"`
}

type publicationHandoff struct {
	directory string
	file      string
	scanID    string
	guard     *output.Guard
	mu        sync.Mutex
	data      []byte
}

func newHandoff(stateDir string, prepared Prepared, now time.Time) (*publicationHandoff, error) {
	root, err := output.EnsurePrivateDir(filepath.Join(stateDir, "publications", "handoffs"))
	if err != nil {
		return nil, err
	}
	name, err := uniqueName(now)
	if err != nil {
		return nil, err
	}
	directory := filepath.Join(root.Path(), name)
	guard, err := output.PreparePrivateDir(directory)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(struct {
		SchemaVersion string `json:"schema_version"`
		Prepared
	}{SchemaVersion: scan.SchemaVersion, Prepared: prepared}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := output.WritePrivateFileAtomic(guard, "publication.json", append(data, '\n')); err != nil {
		return nil, err
	}
	if err := output.WritePrivateFileAtomic(guard, "issues.jsonl", nil); err != nil {
		return nil, err
	}
	return &publicationHandoff{directory: directory, file: filepath.Join(directory, "issues.jsonl"), scanID: prepared.ScanID, guard: guard}, nil
}

func (h *publicationHandoff) append(outcome publishOutcome) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	arguments := map[string]any{
		"team": outcome.input.TeamID, "title": outcome.input.Title,
		"description": outcome.input.Description,
	}
	if outcome.input.ProjectID != "" {
		arguments["project"] = outcome.input.ProjectID
	}
	if outcome.input.Priority != 0 {
		arguments["priority"] = outcome.input.Priority
	}
	record := handoffRecord{
		ScanID:    h.scanID,
		FindingID: outcome.issue.FindingID, OccurrenceID: outcome.issue.OccurrenceID,
		IssueIdentifier: outcome.created.IssueIdentifier, URL: outcome.created.URL,
		Error: outcome.failure, Arguments: arguments,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	next := append(append([]byte(nil), h.data...), encoded...)
	next = append(next, '\n')
	if err := output.WritePrivateFileAtomic(h.guard, "issues.jsonl", next); err != nil {
		return err
	}
	h.data = next
	return nil
}

func (h *publicationHandoff) remove() error {
	if h == nil || h.guard == nil {
		return nil
	}
	if err := h.guard.Validate(); err != nil {
		return err
	}
	for _, name := range []string{"issues.jsonl", "publication.json"} {
		if err := os.Remove(filepath.Join(h.directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(h.directory)
}

func writeReceipt(stateDir string, result Result, now time.Time) (string, error) {
	digest := sha256.Sum256([]byte(result.ScanID))
	guard, err := output.EnsurePrivateDir(filepath.Join(stateDir, "publications", "linear", hex.EncodeToString(digest[:8])))
	if err != nil {
		return "", err
	}
	name, err := uniqueName(now)
	if err != nil {
		return "", err
	}
	name += ".json"
	receipt := struct {
		SchemaVersion string    `json:"schema_version"`
		PublishedAt   time.Time `json:"published_at"`
		Result
	}{SchemaVersion: scan.SchemaVersion, PublishedAt: now.UTC(), Result: result}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", err
	}
	if err := output.WritePrivateFileAtomic(guard, name, append(data, '\n')); err != nil {
		return "", err
	}
	return filepath.Join(guard.Path(), name), nil
}

func uniqueName(now time.Time) (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate publication ID: %w", err)
	}
	return now.UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random), nil
}

func report(observer func(Progress), event Progress) {
	if observer == nil {
		return
	}
	func() {
		defer func() { _ = recover() }()
		observer(event)
	}()
}
