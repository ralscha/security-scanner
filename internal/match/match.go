package match

import (
	"sort"
	"strings"

	"security-scanner/internal/scan"
)

type Pair struct {
	BeforeID   string `json:"before_id"`
	AfterID    string `json:"after_id"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}

type Comparison struct {
	BeforeScanID string         `json:"before_scan_id"`
	AfterScanID  string         `json:"after_scan_id"`
	Persisting   []Pair         `json:"persisting"`
	New          []scan.Finding `json:"new"`
	Reopened     []scan.Finding `json:"reopened"`
	Resolved     []scan.Finding `json:"resolved"`
	Unknown      []scan.Finding `json:"unknown"`
}

// MarkReopened moves new findings seen in an older scan into the reopened class.
func MarkReopened(comparison Comparison, older []scan.FindingsDocument) Comparison {
	known := make(map[string]struct{})
	for _, document := range older {
		for _, finding := range document.Findings {
			if finding.Fingerprint != "" {
				known[finding.Fingerprint] = struct{}{}
			}
		}
	}
	remaining := comparison.New[:0]
	for _, finding := range comparison.New {
		if _, ok := known[finding.Fingerprint]; ok {
			comparison.Reopened = append(comparison.Reopened, finding)
		} else {
			remaining = append(remaining, finding)
		}
	}
	comparison.New = remaining
	return comparison
}

func Compare(before, after scan.FindingsDocument) Comparison {
	result := Comparison{BeforeScanID: before.ScanID, AfterScanID: after.ScanID}
	beforeUsed := make(map[int]bool)
	afterUsed := make(map[int]bool)
	byFingerprint := make(map[string][]int)
	for i, finding := range before.Findings {
		byFingerprint[finding.Fingerprint] = append(byFingerprint[finding.Fingerprint], i)
	}
	for ai, finding := range after.Findings {
		candidates := byFingerprint[finding.Fingerprint]
		if finding.Fingerprint != "" && len(candidates) == 1 && !beforeUsed[candidates[0]] {
			bi := candidates[0]
			beforeUsed[bi], afterUsed[ai] = true, true
			result.Persisting = append(result.Persisting, Pair{BeforeID: before.Findings[bi].ID, AfterID: finding.ID, Confidence: "high", Reason: "fingerprint"})
		}
	}
	for ai, finding := range after.Findings {
		if afterUsed[ai] {
			continue
		}
		candidates := fallbackCandidates(before.Findings, beforeUsed, finding)
		if len(candidates) == 1 {
			bi := candidates[0]
			beforeUsed[bi], afterUsed[ai] = true, true
			result.Persisting = append(result.Persisting, Pair{BeforeID: before.Findings[bi].ID, AfterID: finding.ID, Confidence: "medium", Reason: "cwe_path_title"})
		} else if len(candidates) > 1 {
			afterUsed[ai] = true
			result.Unknown = append(result.Unknown, finding)
		}
	}
	for i, finding := range before.Findings {
		if !beforeUsed[i] {
			result.Resolved = append(result.Resolved, finding)
		}
	}
	for i, finding := range after.Findings {
		if !afterUsed[i] {
			result.New = append(result.New, finding)
		}
	}
	sort.Slice(result.Persisting, func(i, j int) bool { return result.Persisting[i].AfterID < result.Persisting[j].AfterID })
	return result
}

func fallbackCandidates(before []scan.Finding, used map[int]bool, after scan.Finding) []int {
	var result []int
	for i, candidate := range before {
		if used[i] || !samePrimaryCWE(candidate, after) || !samePath(candidate, after) {
			continue
		}
		left := strings.ToLower(strings.TrimSpace(candidate.Title))
		right := strings.ToLower(strings.TrimSpace(after.Title))
		if left == right || strings.Contains(left, right) || strings.Contains(right, left) {
			result = append(result, i)
		}
	}
	return result
}

func samePrimaryCWE(left, right scan.Finding) bool {
	return len(left.CWEIDs) > 0 && len(right.CWEIDs) > 0 && left.CWEIDs[0] == right.CWEIDs[0]
}

func samePath(left, right scan.Finding) bool {
	paths := make(map[string]struct{}, len(left.Locations))
	for _, location := range left.Locations {
		paths[location.Path] = struct{}{}
	}
	for _, location := range right.Locations {
		if _, ok := paths[location.Path]; ok {
			return true
		}
	}
	return false
}
