package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/components/tool/utils"

	"security-scanner/internal/scan"
)

type SubmissionStore struct {
	mu         sync.RWMutex
	inventory  *scan.Inventory
	submission *scan.Submission
}

func NewSubmissionStore(inventory *scan.Inventory) *SubmissionStore {
	return &SubmissionStore{inventory: inventory}
}

func (s *SubmissionStore) Tool() (tool.BaseTool, error) {
	return utils.InferTool("submit_scan", "Submit the final threat model and only findings that survived validation and attack-path analysis. Validation errors are returned so they can be corrected before retrying.", s.submit)
}

func (s *SubmissionStore) Get() (scan.Submission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.submission == nil {
		return scan.Submission{}, false
	}
	return *s.submission, true
}

func (s *SubmissionStore) submit(_ context.Context, submission scan.Submission) (string, error) {
	problems := scan.ValidateSubmission(s.inventory, submission)
	if len(problems) > 0 {
		data, err := json.Marshal(struct {
			Accepted bool     `json:"accepted"`
			Errors   []string `json:"errors"`
		}{Accepted: false, Errors: problems})
		return string(data), err
	}
	s.mu.Lock()
	s.submission = &submission
	s.mu.Unlock()
	return fmt.Sprintf(`{"accepted":true,"finding_count":%d}`, len(submission.Findings)), nil
}
