package remediation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"security-scanner/internal/history"
	"security-scanner/internal/scan"
	"security-scanner/internal/triage"
)

type Input struct {
	Target string
	Text   string
}

func ResolveInput(specification, explicitTarget string) (Input, error) {
	specification = strings.TrimSpace(specification)
	if specification == "" {
		return Input{}, fmt.Errorf("finding or prompt is required")
	}
	if strings.HasPrefix(specification, "scan-") && strings.Contains(specification, ":") {
		return resolveOccurrence(specification)
	}
	if info, err := os.Stat(specification); err == nil && !info.IsDir() {
		return resolveArtifact(specification, explicitTarget)
	}
	if strings.TrimSpace(explicitTarget) == "" {
		explicitTarget = "."
	}
	return Input{Target: explicitTarget, Text: specification}, nil
}

func resolveOccurrence(occurrenceID string) (Input, error) {
	scanID, findingID, err := triage.ParseOccurrenceID(occurrenceID)
	if err != nil {
		return Input{}, err
	}
	store, err := history.DefaultStore()
	if err != nil {
		return Input{}, err
	}
	record, err := store.Get(scanID)
	if err != nil {
		return Input{}, err
	}
	result, err := history.LoadResult(record)
	if err != nil {
		return Input{}, err
	}
	for _, finding := range result.Findings.Findings {
		if finding.ID == findingID {
			data, err := json.Marshal(finding)
			return Input{Target: record.Target, Text: string(data)}, err
		}
	}
	return Input{}, fmt.Errorf("finding %q does not exist in scan %q", findingID, scanID)
}

func resolveArtifact(path, explicitTarget string) (Input, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Input{}, fmt.Errorf("read findings input: %w", err)
	}
	var document scan.FindingsDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return Input{}, fmt.Errorf("decode findings input: %w", err)
	}
	if document.ScanID == "" {
		return Input{}, fmt.Errorf("findings input has no scan_id")
	}
	target := strings.TrimSpace(explicitTarget)
	if target == "" {
		var manifest scan.ScanManifest
		manifestData, err := os.ReadFile(filepath.Join(filepath.Dir(path), "scan-manifest.json"))
		if err != nil {
			return Input{}, fmt.Errorf("resolve target from adjacent scan-manifest.json: %w", err)
		}
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			return Input{}, fmt.Errorf("decode adjacent scan manifest: %w", err)
		}
		target = manifest.Target
	}
	return Input{Target: target, Text: string(data)}, nil
}
