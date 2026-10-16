package data

import (
	"errors"
	"net/http"
	"net/http/httptest"
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
		{"example.com", true},    // TLD = com
		{"test.net", true},       // TLD = net
		{"example.org", true},    // TLD = org
		{"example.uk", true},     // TLD = uk
		{"example.test", false},  // TLD = test (not in list)
		{"example.local", false}, // TLD = local (not in list)
		{"localhost", false},     // No TLD
	}

	for _, tt := range tests {
		got := loader.TLDRegistered(tt.domain)
		if got != tt.want {
			t.Errorf("TLDRegistered(%s) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestSetDataDirIsUsedForDefaultPSLPath(t *testing.T) {
	tmpDir := t.TempDir()
	content := "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "public_suffix_list.dat"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{}
	loader.SetDataDir(tmpDir)
	if err := loader.LoadPSL(""); err != nil {
		t.Fatalf("LoadPSL from data dir: %v", err)
	}
	if !loader.IsPublicSuffix("com") {
		t.Error("PSL from configured data dir was not loaded")
	}

	loader.SetDataDir("")
	if loader.dataDir != tmpDir {
		t.Errorf("SetDataDir(\"\") changed dataDir to %q", loader.dataDir)
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
		domain   string
		wildcard string
		expected bool
	}{
		{"com.ck", "*.ck", true},
		{"edu.ck", "*.ck", true},
		{"ck", "*.ck", false}, // TLD itself doesn't match wildcard
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

func TestDownloadPSL(t *testing.T) {
	const list = "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n"
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
		wantErr string
	}{
		{
			name:    "replaces the list",
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(list)) },
			want:    list,
		},
		{
			name: "keeps the list on an error status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			},
			want:    "previous",
			wantErr: "status 503",
		},
		{
			name: "keeps the list when the download is too large",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(make([]byte, maxPSLBytes+1))
			},
			want:    "previous",
			wantErr: "exceeds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()
			dir := t.TempDir()
			dest := filepath.Join(dir, "public_suffix_list.dat")
			if err := os.WriteFile(dest, []byte("previous"), 0o644); err != nil {
				t.Fatal(err)
			}

			err := DownloadPSL(server.URL, dest)
			if tt.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
			}
			got, readErr := os.ReadFile(dest)
			if readErr != nil || string(got) != tt.want {
				t.Fatalf("list = %q, %v; want %q", got, readErr, tt.want)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 1 {
				t.Fatalf("directory holds %d files, want only the list", len(entries))
			}
		})
	}
}

func TestLoadPSLReportsMissingList(t *testing.T) {
	loader := &Loader{}
	if err := loader.LoadPSL(filepath.Join(t.TempDir(), "missing.dat")); !errors.Is(err, ErrPSLNotFound) {
		t.Errorf("LoadPSL of a missing file = %v, want ErrPSLNotFound", err)
	}
	if loader.Loaded() {
		t.Error("Loaded() after a failed load")
	}

	list := filepath.Join(t.TempDir(), "public_suffix_list.dat")
	if err := os.WriteFile(list, []byte("// ===BEGIN ICANN DOMAINS===\ncom\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := loader.LoadPSL(list); err != nil || !loader.Loaded() {
		t.Fatalf("LoadPSL(%s) = %v, Loaded() = %v", list, err, loader.Loaded())
	}
}

// Without a list file or data directory, the embedded snapshot is used; a
// data directory list takes precedence.
func TestLoadPSLFallsBackToEmbeddedSnapshot(t *testing.T) {
	loader := &Loader{}
	if err := loader.LoadPSL(""); err != nil {
		t.Fatalf("LoadPSL without a list = %v", err)
	}
	if !loader.TLDRegistered("example.com") || !loader.IsPublicSuffix("github.io") {
		t.Error("embedded snapshot lacks com or github.io")
	}
	if source := loader.psl.SourceFile; source != "embedded snapshot "+EmbeddedPSLVersion() || EmbeddedPSLVersion() == "unknown" {
		t.Errorf("source = %q", source)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "public_suffix_list.dat"), []byte("// ===BEGIN ICANN DOMAINS===\ntest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loader = &Loader{dataDir: dir}
	if err := loader.LoadPSL(""); err != nil || loader.TLDRegistered("example.com") || !loader.TLDRegistered("x.test") {
		t.Errorf("data directory list was not preferred: %v", err)
	}
}

func TestIsICANNPublicSuffix(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test_psl.dat")
	content := `// ===BEGIN ICANN DOMAINS===
com
co.uk
*.ck
!www.ck
公司.cn
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	loader := &Loader{}
	if err := loader.LoadPSL(testFile); err != nil {
		t.Fatal(err)
	}
	for domain, want := range map[string]bool{
		"com":           true,
		"CO.UK.":        true,
		"example.co.uk": false,
		"foo.ck":        true,  // *.ck
		"www.ck":        false, // !www.ck
		"ck":            true,  // implicit "*" rule
		"local":         true,  // implicit "*" rule
		"xn--55qx5d.cn": true,  // 公司.cn as an A-label
		"github.io":     false, // PRIVATE section
		"example.com":   false,
		"":              false,
	} {
		if got := loader.IsICANNPublicSuffix(domain); got != want {
			t.Errorf("IsICANNPublicSuffix(%q) = %v, want %v", domain, got, want)
		}
	}
}
