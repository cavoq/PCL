package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ProfileAssumption is a profile the user assumes for inputs of its role,
// or for the one input whose SHA-256 fingerprint starts with Fingerprint.
type ProfileAssumption struct {
	Profile     string
	Fingerprint string // lowercase hex prefix; empty for every input of the role
}

func (a ProfileAssumption) String() string {
	if a.Fingerprint == "" {
		return a.Profile
	}
	return a.Profile + "=" + a.Fingerprint
}

// Matches reports whether the assumption selects the DER-encoded input raw.
func (a ProfileAssumption) Matches(raw []byte) bool {
	if a.Fingerprint == "" {
		return true
	}
	fingerprint := sha256.Sum256(raw)
	return strings.HasPrefix(hex.EncodeToString(fingerprint[:]), a.Fingerprint)
}

// ParseProfileAssumptions parses PROFILE or PROFILE=SHA256-PREFIX values. A
// prefix has at least 8 hex digits and may separate bytes with colons. Each
// profile must be declared by one of policies.
func ParseProfileAssumptions(values []string, policies []Policy) ([]ProfileAssumption, error) {
	declared := make(map[string]bool)
	for _, p := range policies {
		for _, profile := range p.Profiles {
			declared[profile.ID] = true
		}
	}
	assumptions := make([]ProfileAssumption, 0, len(values))
	for _, value := range values {
		name, fingerprint, _ := strings.Cut(value, "=")
		if !declared[name] {
			return nil, fmt.Errorf("assumed profile %q is not declared by a selected policy", name)
		}
		fingerprint = strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
		if strings.Contains(value, "=") {
			if _, err := hex.DecodeString(fingerprint + strings.Repeat("0", len(fingerprint)%2)); err != nil ||
				len(fingerprint) < 8 || len(fingerprint) > 2*sha256.Size {
				return nil, fmt.Errorf("assumed profile %s: %q is not a SHA-256 fingerprint prefix of 8 to 64 hex digits", name, fingerprint)
			}
		}
		assumptions = append(assumptions, ProfileAssumption{Profile: name, Fingerprint: fingerprint})
	}
	return assumptions, nil
}

// profileRole returns the role of the profile id in p.
func profileRole(p Policy, id string) (string, bool) {
	for _, profile := range p.Profiles {
		if profile.ID == id {
			return profile.Role, true
		}
	}
	return "", false
}

// AssumesRole reports whether p declares the profile id for role.
func AssumesRole(p Policy, id, role string) bool {
	declared, ok := profileRole(p, id)
	return ok && declared == role
}
