package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestRegex(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		pattern string
		want    bool
	}{
		{"simple match", "hello", "hello", true},
		{"partial match", "hello world", "world", true},
		{"no match", "hello", "world", false},
		{"email pattern", "user@example.com", `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, true},
		{"invalid email", "not-an-email", `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, false},
		{"dns name", "www.example.com", `^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`, true},
		{"wildcard dns", "*.example.com", `^\*\.([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`, true},
		{"uri pattern", "https://example.com/path", `^https?://`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			op := Regex{}
			got, err := op.Evaluate(n, nil, []any{tt.pattern})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Regex.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegexNilNode(t *testing.T) {
	op := Regex{}
	got, _ := op.Evaluate(nil, nil, []any{".*"})
	if got != false {
		t.Error("nil node should return false")
	}
}

func TestRegexInvalidPattern(t *testing.T) {
	n := node.New("test", "hello")
	op := Regex{}
	_, err := op.Evaluate(n, nil, []any{"[invalid"})
	if err == nil {
		t.Error("should error with invalid pattern")
	}
}

func TestRegexNonString(t *testing.T) {
	n := node.New("test", 123)
	op := Regex{}
	got, err := op.Evaluate(n, nil, []any{".*"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("non-string value should return false")
	}
}

func TestNotRegex(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		pattern string
		want    bool
	}{
		{"no match returns true", "hello", "world", true},
		{"match returns false", "hello", "hello", false},
		{"weak algo check", "SHA256-RSA", "^(MD5|SHA1)", true},
		{"weak algo detected", "SHA1-RSA", "^(MD5|SHA1)", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			op := NotRegex{}
			got, err := op.Evaluate(n, nil, []any{tt.pattern})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("NotRegex.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegexName(t *testing.T) {
	op := Regex{}
	if op.Name() != "regex" {
		t.Error("wrong name")
	}
}

func TestNotRegexName(t *testing.T) {
	op := NotRegex{}
	if op.Name() != "notRegex" {
		t.Error("wrong name")
	}
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
