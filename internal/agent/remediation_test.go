package agent

import (
	"context"
	"testing"

	"security-scanner/internal/remediation"
	"security-scanner/internal/scan"
)

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
