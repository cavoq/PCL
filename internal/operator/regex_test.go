package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestRegexOperators(t *testing.T) {
	const email = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	match := func(name string, op Operator, value any, pattern string, want bool) evaluationCase {
		return evaluationCase{name: name, op: op, node: node.New("test", value), operands: []any{pattern}, want: want}
	}
	checkEvaluations(t, nil, []evaluationCase{
		match("regex: simple match", Regex{}, "hello", "hello", true),
		match("regex: partial match", Regex{}, "hello world", "world", true),
		match("regex: no match", Regex{}, "hello", "world", false),
		match("regex: email pattern", Regex{}, "user@example.com", email, true),
		match("regex: invalid email", Regex{}, "not-an-email", email, false),
		match("regex: dns name", Regex{}, "www.example.com", `^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`, true),
		match("regex: wildcard dns", Regex{}, "*.example.com", `^\*\.([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`, true),
		match("regex: uri pattern", Regex{}, "https://example.com/path", `^https?://`, true),
		match("regex: non-string value", Regex{}, 123, ".*", false),
		{name: "regex: nil node", op: Regex{}, operands: []any{".*"}},
		{name: "regex: invalid pattern", op: Regex{}, node: node.New("test", "hello"), operands: []any{"[invalid"}, wantErr: true},
		match("notRegex: no match returns true", NotRegex{}, "hello", "world", true),
		match("notRegex: match returns false", NotRegex{}, "hello", "hello", false),
		match("notRegex: weak algo check", NotRegex{}, "SHA256-RSA", "^(MD5|SHA1)", true),
		match("notRegex: weak algo detected", NotRegex{}, "SHA1-RSA", "^(MD5|SHA1)", false),
	})
}

func TestRegexCaching(t *testing.T) {
	pattern := `^test-pattern-\d+$`
	n := node.New("test", "test-pattern-123")
	op := Regex{}

	got1, err := op.Evaluate(n, nil, []any{pattern})
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	if !got1 {
		t.Error("first call should match")
	}

	got2, err := op.Evaluate(n, nil, []any{pattern})
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if !got2 {
		t.Error("second call should match")
	}

	regexCacheMu.RLock()
	_, cached := regexCache[pattern]
	regexCacheMu.RUnlock()
	if !cached {
		t.Error("pattern should be cached")
	}
}

func TestGetCompiledRegexInvalidPattern(t *testing.T) {
	_, err := getCompiledRegex("[invalid")
	if err == nil {
		t.Error("should return error for invalid pattern")
	}
}
