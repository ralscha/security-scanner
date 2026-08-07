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

func TestSpecialistInstructionIncludesFollowUpPrompt(t *testing.T) {
	custom := "\nCross-check taint paths against authorization guards.\n"
	instruction := specialistInstruction(discoveryPrompt, custom)
	if !strings.Contains(instruction, "Custom follow-up prompt:\nCross-check taint paths against authorization guards.") {
		t.Fatalf("custom follow-up prompt was not appended: %q", instruction)
	}
}
