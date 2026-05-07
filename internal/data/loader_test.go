package data

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePSLFile(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_psl.dat")

	content := `// Public Suffix List test data
// ===BEGIN ICANN DOMAINS===
com
net
org
edu
gov
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
blogspot.com
appspot.com
// ===END PRIVATE DOMAINS===
`

	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	psl, err := parsePSLFile(testFile)
	if err != nil {
		t.Fatalf("Failed to parse PSL file: %v", err)
	}

	// Verify ICANN domains
	expectedICANN := []string{"com", "net", "org", "edu", "gov"}
	for _, domain := range expectedICANN {
		if !psl.ICANNDomains[domain] {
			t.Errorf("Expected %s in ICANNDomains, but not found", domain)
		}
	}

	// Verify Private domains
	expectedPrivate := []string{"github.io", "blogspot.com", "appspot.com"}
	for _, domain := range expectedPrivate {
		if !psl.PrivateDomains[domain] {
			t.Errorf("Expected %s in PrivateDomains, but not found", domain)
		}
	}

	// Verify counts
	if len(psl.ICANNDomains) != 5 {
		t.Errorf("Expected 5 ICANN domains, got %d", len(psl.ICANNDomains))
	}
	if len(psl.PrivateDomains) != 3 {
		t.Errorf("Expected 3 private domains, got %d", len(psl.PrivateDomains))
	}
	if len(psl.AllPublicSuffixes) != 8 {
		t.Errorf("Expected 8 total public suffixes, got %d", len(psl.AllPublicSuffixes))
	}
}

func TestIsPublicSuffix(t *testing.T) {
	// Setup test loader
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_psl.dat")

	content := `// ===BEGIN ICANN DOMAINS===
com
net
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{dataDir: tmpDir}
	if err := loader.LoadPSL(testFile); err != nil {
		t.Fatalf("Failed to load PSL: %v", err)
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"com", true},
		{"net", true},
		{"github.io", true},
		{"example", false},
		{"unknown.io", false},
	}

	for _, tt := range tests {
		got := loader.IsPublicSuffix(tt.domain)
		if got != tt.want {
			t.Errorf("IsPublicSuffix(%s) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestTLDRegistered(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_psl.dat")

	content := `// ===BEGIN ICANN DOMAINS===
com
net
org
uk
co.uk
// ===END ICANN DOMAINS===
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{dataDir: tmpDir}
	if err := loader.LoadPSL(testFile); err != nil {
		t.Fatalf("Failed to load PSL: %v", err)
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},      // TLD = com
		{"test.net", true},         // TLD = net
		{"example.org", true},      // TLD = org
		{"example.uk", true},       // TLD = uk
		{"example.test", false},    // TLD = test (not in list)
		{"example.local", false},   // TLD = local (not in list)
		{"localhost", false},       // No TLD
	}

	for _, tt := range tests {
		got := loader.TLDRegistered(tt.domain)
		if got != tt.want {
			t.Errorf("TLDRegistered(%s) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestLoaderWithoutPSL(t *testing.T) {
	loader := &Loader{dataDir: ""}

	// Should return false when no PSL loaded
	if loader.IsPublicSuffix("com") {
		t.Error("IsPublicSuffix should return false when PSL not loaded")
	}
	if loader.TLDRegistered("example.com") {
		t.Error("TLDRegistered should return false when PSL not loaded")
	}

	icann, private, loaded := loader.Stats()
	if loaded {
		t.Error("Stats should indicate not loaded")
	}
	if icann != 0 || private != 0 {
		t.Error("Stats should return 0 counts when not loaded")
	}
}

func TestGetDefaultDataDir(t *testing.T) {
	dir := getDefaultDataDir()
	// Should return empty string if no data directory exists
	// Or return path if data directory exists in cwd or home
	t.Logf("Default data dir: %s", dir)
}

func TestParsePSLWithCommentsAndWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_psl.dat")

	content := `// This is a comment
// Another comment

   com

	net

// ===BEGIN PRIVATE DOMAINS===
// Comment in private section
  github.io
// ===END PRIVATE DOMAINS===
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	psl, err := parsePSLFile(testFile)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	// Should handle whitespace trimming
	if !psl.ICANNDomains["com"] {
		t.Error("Should have 'com' after trimming whitespace")
	}
	if !psl.ICANNDomains["net"] {
		t.Error("Should have 'net' after trimming whitespace")
	}
	if !psl.PrivateDomains["github.io"] {
		t.Error("Should have 'github.io' after trimming whitespace")
	}
}

func TestPSLWildcardDomains(t *testing.T) {
	// PSL contains wildcard entries like *.ck which means all .ck subdomains
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_psl.dat")

	content := `// ===BEGIN ICANN DOMAINS===
*.ck
*.jp
// ===END ICANN DOMAINS===
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	psl, err := parsePSLFile(testFile)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	// Wildcards are stored as-is (e.g., "*.ck")
	if !psl.ICANNDomains["*.ck"] {
		t.Error("Should have '*.ck' wildcard entry")
	}

	// Test wildcard matching logic separately
	tests := []struct {
		domain    string
		wildcard  string
		expected  bool
	}{
		{"com.ck", "*.ck", true},
		{"edu.ck", "*.ck", true},
		{"ck", "*.ck", false},      // TLD itself doesn't match wildcard
		{"example.jp", "*.jp", true},
	}

	for _, tt := range tests {
		matches := matchesWildcard(tt.domain, tt.wildcard)
		if matches != tt.expected {
			t.Errorf("matchesWildcard(%s, %s) = %v, want %v", tt.domain, tt.wildcard, matches, tt.expected)
		}
	}
}

// matchesWildcard checks if a domain matches a PSL wildcard entry.
// PSL wildcard "*.ck" means any second-level domain under .ck is a public suffix.
func matchesWildcard(domain, wildcard string) bool {
	if !strings.HasPrefix(wildcard, "*.") {
		return false
	}

	// Get the suffix part after "*."
	suffix := strings.TrimPrefix(wildcard, "*.")

	// Check if domain ends with the suffix and has exactly one extra label
	labels := strings.Split(domain, ".")
	suffixLabels := strings.Split(suffix, ".")

	if len(labels) == len(suffixLabels)+1 && strings.HasSuffix(domain, "."+suffix) {
		return true
	}

	return false
}