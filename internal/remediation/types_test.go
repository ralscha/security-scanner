package remediation

import (
	"testing"

	"security-scanner/internal/scan"
)

func TestValidateValidationRequiresGroundedEvidence(t *testing.T) {
	inventory := &scan.Inventory{Files: []scan.File{{Path: "app.go", Lines: 10, Reviewable: true}}}
	valid := Validation{Verdict: "true_positive", Rationale: "reachable", RecommendedAction: "fix it", Evidence: []scan.Location{{Path: "app.go", StartLine: 2, EndLine: 3}}}
	if problems := ValidateValidation(inventory, valid); len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	valid.Evidence[0].Path = "../outside"
	if problems := ValidateValidation(inventory, valid); len(problems) == 0 {
		t.Fatal("expected outside evidence to be rejected")
	}
}

func TestValidatePatchRejectsUnboundedOrUnknownChanges(t *testing.T) {
	inventory := &scan.Inventory{Files: []scan.File{{Path: "app.go", Lines: 10, Reviewable: true}}}
	proposal := PatchProposal{Summary: "fix", Rationale: "reason", Verification: []string{"go test ./..."}, Changes: []Change{{Path: "app.go", StartLine: 2, EndLine: 3, Description: "validate", Replacement: "safe()"}}}
	if problems := ValidatePatch(inventory, proposal); len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	proposal.Changes[0].EndLine = 100
	if problems := ValidatePatch(inventory, proposal); len(problems) == 0 {
		t.Fatal("expected invalid range")
	}
}
