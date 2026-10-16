package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseProfileAssumptions(t *testing.T) {
	policies := []Policy{{ID: "p", Profiles: []Profile{{ID: "cross", Role: "intermediate"}}}}
	assumptions, err := ParseProfileAssumptions([]string{"cross", "cross=AB:CD:EF:01", "cross=abcdef012"}, policies)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{assumptions[0].String(), assumptions[1].String(), assumptions[2].String()}; strings.Join(got, " ") != "cross cross=abcdef01 cross=abcdef012" {
		t.Errorf("assumptions = %v", got)
	}
	for value, want := range map[string]string{
		"crossed":                          `"crossed" is not declared`,
		"cross=abc":                        "8 to 64 hex digits",
		"cross=ghijklmn":                   "8 to 64 hex digits",
		"cross=" + strings.Repeat("a", 65): "8 to 64 hex digits",
	} {
		if _, err := ParseProfileAssumptions([]string{value}, policies); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error = %v, want %q", value, err, want)
		}
	}
}

func TestProfileAssumptionMatchesFingerprintPrefix(t *testing.T) {
	raw := []byte("certificate")
	sum := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(sum[:])
	for prefix, want := range map[string]bool{"": true, fingerprint[:8]: true, fingerprint: true, "00000000": false} {
		if got := (ProfileAssumption{Profile: "p", Fingerprint: prefix}).Matches(raw); got != want {
			t.Errorf("prefix %q matches = %v, want %v", prefix, got, want)
		}
	}
}
