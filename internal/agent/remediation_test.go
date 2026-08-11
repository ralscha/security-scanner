package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"

	"security-scanner/internal/remediation"
	"security-scanner/internal/scan"
)

type failingReviewModel struct{}

func (failingReviewModel) Generate(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
	return nil, errors.New("large review reached model")
}

func (failingReviewModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, errors.New("large review reached model")
}

func (failingReviewModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return failingReviewModel{}, nil
}

func TestValidationStoreAcceptsGroundedTrueAndFalsePositiveVerdicts(t *testing.T) {
	inventory := &scan.Inventory{Files: []scan.File{{Path: "app.go", Lines: 20, Reviewable: true}}}
	for _, verdict := range []string{"true_positive", "false_positive"} {
		store := &validationStore{inventory: inventory}
		result := remediation.Validation{
			Verdict: verdict, Rationale: "The exact caller and control were inspected.", RecommendedAction: "Record the evidence.",
			Evidence: []scan.Location{{Path: "app.go", StartLine: 5, EndLine: 8, Role: "evidence"}},
		}
		if _, err := store.submit(context.Background(), result); err != nil {
			t.Fatalf("submit %s: %v", verdict, err)
		}
		stored, err := store.get()
		if err != nil || stored.Verdict != verdict {
			t.Fatalf("stored %s result = %#v, err = %v", verdict, stored, err)
		}
	}
}

func TestPatchStoreAcceptsBoundedProposal(t *testing.T) {
	inventory := &scan.Inventory{Files: []scan.File{{Path: "app.go", Lines: 20, Reviewable: true}}}
	store := &patchStore{inventory: inventory}
	proposal := remediation.PatchProposal{
		Summary: "Validate the command argument", Rationale: "Rejecting control characters blocks the demonstrated path.",
		Changes:      []remediation.Change{{Path: "app.go", StartLine: 5, EndLine: 8, Description: "validate before use", Replacement: "validate(input)"}},
		Verification: []string{"run the command-handler unit tests"},
	}
	if _, err := store.submit(context.Background(), proposal); err != nil {
		t.Fatal(err)
	}
	stored, err := store.get()
	if err != nil || len(stored.Changes) != 1 {
		t.Fatalf("stored proposal = %#v, err = %v", stored, err)
	}
}

func TestReviewerAcceptsInputAboveLegacyLimit(t *testing.T) {
	reviewer := NewEinoReviewer(failingReviewModel{}, Config{MaxIterations: 1}, &scan.Inventory{Root: t.TempDir()})
	_, err := reviewer.Validate(context.Background(), strings.Repeat("evidence ", 10_000))
	if err == nil || !strings.Contains(err.Error(), "large review reached model") {
		t.Fatalf("large review did not reach model: %v", err)
	}
}
