package redact

import (
	"io"
	"regexp"
	"strings"
)

var (
	privateKeyPattern    = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]{0,48}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,48}PRIVATE KEY-----|$)`)
	credentialKeyPattern = regexp.MustCompile(`(?i)\b[A-Za-z0-9_-]{0,64}(?:api[_-]?key|access[_-]?key(?:[_-]?id)?|private[_-]?key|authorization|auth|token|secret|credential|signature|sig|password|passwd)[A-Za-z0-9_-]{0,64}\b`)
	commonTokenPattern   = regexp.MustCompile(`(?i)\b(?:sk-(?:proj-)?|github_pat_|gh[pousr]_|npm_)[A-Za-z0-9_*=-]{8,}`)
	authorizationPattern = regexp.MustCompile(`(?i)\b(Bearer|Basic|Token)((?:\s|%20|\+)+)[A-Za-z0-9.%_~+/*=-]+`)
	URLUserInfoPattern   = regexp.MustCompile(`(?i)\b((?:https?|ssh|git\+ssh)://)[^\s/@]+@`)
)

// Text removes credential-shaped values before errors cross a display or
// persistence boundary. It deliberately favors over-redaction over leaking a
// provider credential into logs, JSON progress, or durable scan state.
func Text(message string) string {
	message = privateKeyPattern.ReplaceAllString(message, "[redacted private key]")
	message = redactAssignments(message)
	message = commonTokenPattern.ReplaceAllString(message, "[redacted]")
	message = authorizationPattern.ReplaceAllString(message, "$1$2[redacted]")
	message = URLUserInfoPattern.ReplaceAllString(message, "$1[redacted]@")
	return message
}

func redactAssignments(message string) string {
	matches := credentialKeyPattern.FindAllStringIndex(message, -1)
	if len(matches) == 0 {
		return message
	}
	var result strings.Builder
	consumed := 0
	for _, match := range matches {
		if match[0] < consumed {
			continue
		}
		delimiter := assignmentDelimiter(message, match[1])
		if delimiter < 0 {
			continue
		}
		valueStart := delimiter + 1
		for valueStart < len(message) && (message[valueStart] == ' ' || message[valueStart] == '\t') {
			valueStart++
		}
		if valueStart >= len(message) {
			continue
		}
		contentStart, valueEnd := credentialValueBounds(message, valueStart, isAuthorizationKey(message[match[0]:match[1]]))
		if contentStart >= valueEnd {
			continue
		}
		result.WriteString(message[consumed:contentStart])
		result.WriteString("[redacted]")
		consumed = valueEnd
	}
	if consumed == 0 {
		return message
	}
	result.WriteString(message[consumed:])
	return result.String()
}

func assignmentDelimiter(message string, start int) int {
	for i := start; i < len(message) && i-start <= 12; i++ {
		switch message[i] {
		case ':', '=':
			return i
		case ' ', '\t', '\\', '\'', '"':
			continue
		default:
			return -1
		}
	}
	return -1
}

func credentialValueBounds(message string, start int, authorization bool) (int, int) {
	openingSlashes := 0
	for start+openingSlashes < len(message) && message[start+openingSlashes] == '\\' {
		openingSlashes++
	}
	quoteAt := start + openingSlashes
	if quoteAt < len(message) && (message[quoteAt] == '"' || message[quoteAt] == '\'') {
		quote := message[quoteAt]
		contentStart := quoteAt + 1
		for i := contentStart; i < len(message); i++ {
			if message[i] != quote {
				continue
			}
			slashes := 0
			for j := i - 1; j >= contentStart && message[j] == '\\'; j-- {
				slashes++
			}
			if (openingSlashes == 0 && slashes%2 == 0) || (openingSlashes > 0 && slashes == openingSlashes) {
				return contentStart, i - slashes
			}
		}
		return contentStart, len(message)
	}
	end := start
	for end < len(message) {
		if strings.ContainsRune(",;\r\n}&]", rune(message[end])) {
			break
		}
		if !authorization && (message[end] == ' ' || message[end] == '\t') {
			break
		}
		end++
	}
	return start, end
}

func isAuthorizationKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
	return strings.Contains(normalized, "authorization") || normalized == "auth" || strings.HasSuffix(normalized, "auth")
}

type redactingWriter struct{ destination io.Writer }

// Writer redacts each write before forwarding it while preserving the input
// writer contract for callers such as fmt and flag.FlagSet.
func Writer(destination io.Writer) io.Writer {
	return &redactingWriter{destination: destination}
}

func (w *redactingWriter) Write(data []byte) (int, error) {
	redacted := []byte(Text(string(data)))
	written, err := w.destination.Write(redacted)
	if err != nil {
		return 0, err
	}
	if written != len(redacted) {
		return 0, io.ErrShortWrite
	}
	return len(data), nil
}
