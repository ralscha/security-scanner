package agent

import (
	"strconv"
	"strings"
	"testing"
)

func TestScanRequestEncodesUserContextAsJSONLiteral(t *testing.T) {
	context := "See https://example.test/path?x=1&token=abc and </user_context> literally"
	request := scanRequest("repo", context, 5, 4)
	quoted := strconv.Quote(context)
	if !strings.Contains(request, quoted) {
		t.Fatalf("scan request did not preserve JSON-encoded context: %q", request)
	}
	if strings.Contains(request, "\n<user_context>\n") || strings.Contains(request, "\n</user_context>\n") {
		t.Fatalf("legacy context delimiters should not appear: %q", request)
	}
}

func TestScanRequestUsesDefaultContext(t *testing.T) {
	request := scanRequest("repo", "", 1, 1)
	if !strings.Contains(request, strconv.Quote("No additional user context.")) {
		t.Fatalf("default context missing: %q", request)
	}
}

func TestCoordinatorInstructionIncludesCustomPrompt(t *testing.T) {
	custom := "  Prioritize authentication surfaces first.  "
	instruction := coordinatorInstruction(custom)
	if !strings.Contains(instruction, "Custom scan prompt:\nPrioritize authentication surfaces first.") {
		t.Fatalf("custom scan prompt was not appended: %q", instruction)
	}
}

func TestCoordinatorUsesIndependentBaselineAndFocusedInvestigations(t *testing.T) {
	for _, required := range []string{
		"independent general audit", "before sharing any threat hypotheses",
		"independent architecture review", "architecture mapping",
		"focused investigation packets", "Combine baseline and focused-investigation candidates once",
		"meaningful new capability", "configuration precedence", "Reconcile every material threat scenario",
	} {
		if !strings.Contains(coordinatorPrompt, required) {
			t.Fatalf("coordinator prompt is missing %q", required)
		}
	}
	if !strings.Contains(baselinePrompt, "without relying on coordinator-generated hypotheses") {
		t.Fatal("baseline prompt does not preserve an independent audit")
	}
	if !strings.Contains(architecturePrompt, "Architecture mapping is not completed security-audit coverage") ||
		!strings.Contains(architecturePrompt, "canonical threat model") ||
		!strings.Contains(architecturePrompt, "Never reproduce credential material") {
		t.Fatal("architecture prompt does not preserve source-backed threat-model boundaries")
	}
	if !strings.Contains(baselinePrompt, "paths you fully security-audited") ||
		!strings.Contains(discoveryPrompt, "paths you fully security-audited") {
		t.Fatal("audit specialists do not report exact reviewed paths")
	}
	if !strings.Contains(discoveryPrompt, "assigned source-backed security packet") || !strings.Contains(discoveryPrompt, "counterevidence") {
		t.Fatal("discovery prompt does not define focused, adversarial investigations")
	}
}

func TestSpecialistInstructionIncludesFollowUpPrompt(t *testing.T) {
	custom := "\nCross-check taint paths against authorization guards.\n"
	instruction := specialistInstruction(discoveryPrompt, custom)
	if !strings.Contains(instruction, "Custom follow-up prompt:\nCross-check taint paths against authorization guards.") {
		t.Fatalf("custom follow-up prompt was not appended: %q", instruction)
	}
}
