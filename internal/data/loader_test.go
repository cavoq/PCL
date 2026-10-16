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

// loadList writes content to a list file and loads it into a new loader.
func loadList(t *testing.T, content string) *Loader {
	t.Helper()
	file := filepath.Join(t.TempDir(), "test_psl.dat")
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	loader := &Loader{}
	if err := loader.LoadPSL(file); err != nil {
		t.Fatalf("LoadPSL: %v", err)
	}
	return loader
}

func TestLoadPSLSections(t *testing.T) {
	loader := loadList(t, `// Public Suffix List test data
// ===BEGIN ICANN DOMAINS===
com
net
org
edu
co.uk
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
blogspot.com
appspot.com
// ===END PRIVATE DOMAINS===
`)
	if icann, private, loaded := loader.Stats(); icann != 5 || private != 3 || !loaded {
		t.Errorf("Stats() = %d, %d, %v; want 5 ICANN and 3 private rules", icann, private, loaded)
	}
	for domain, want := range map[string][2]bool{ // {IsPublicSuffix, IsICANNPublicSuffix}
		"co.uk":        {true, true},
		"blogspot.com": {true, false},
		"x.github.io":  {false, false},
		"example.com":  {false, false},
	} {
		if got := [2]bool{loader.IsPublicSuffix(domain), loader.IsICANNPublicSuffix(domain)}; got != want {
			t.Errorf("%s: IsPublicSuffix, IsICANNPublicSuffix = %v, want %v", domain, got, want)
		}
	}
}

func TestIsPublicSuffix(t *testing.T) {
	loader := loadList(t, `// ===BEGIN ICANN DOMAINS===
com
net
*.ck
!www.ck
公司.cn
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
*.compute.example.com
// ===END PRIVATE DOMAINS===
`)
	for domain, want := range map[string]bool{
		"com":                    true,
		"github.io":              true,
		"GitHub.IO.":             true,
		"foo.ck":                 true,  // *.ck
		"www.ck":                 false, // !www.ck
		"xn--55qx5d.cn":          true,  // 公司.cn as an A-label
		"eu.compute.example.com": true,  // private wildcard
		"example":                true,  // implicit "*" rule
		"unknown.io":             false,
		"user.github.io":         false,
		"":                       false,
	} {
		if got := loader.IsPublicSuffix(domain); got != want {
			t.Errorf("IsPublicSuffix(%q) = %v, want %v", domain, got, want)
		}
	}
}

func TestTLDRegistered(t *testing.T) {
	loader := loadList(t, `// ===BEGIN ICANN DOMAINS===
com
net
org
uk
co.uk
*.ck
!www.ck
рф
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.dev
// ===END PRIVATE DOMAINS===
`)

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},         // TLD = com
		{"test.net", true},            // TLD = net
		{"EXAMPLE.ORG.", true},        // case and a trailing dot are ignored
		{"example.uk", true},          // TLD = uk
		{"example.ck", true},          // only *.ck names ck
		{"example.xn--p1ai", true},    // рф as an A-label
		{"example.test", false},       // TLD = test (not in list)
		{"example.local", false},      // TLD = local (not in list)
		{"localhost", false},          // No TLD
		{"example.github.dev", false}, // dev appears only in the PRIVATE section
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

func TestLoadPSLWithCommentsAndWhitespace(t *testing.T) {
	loader := loadList(t, `// This is a comment
// Another comment

   com

	net

// ===BEGIN PRIVATE DOMAINS===
// Comment in private section
  github.io
// ===END PRIVATE DOMAINS===
`)
	if !loader.TLDRegistered("example.com") || !loader.TLDRegistered("example.net") {
		t.Error("indented ICANN rules were not loaded")
	}
	if !loader.IsPublicSuffix("github.io") || loader.IsICANNPublicSuffix("github.io") {
		t.Error("indented private rule was not loaded into the PRIVATE section")
	}
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

// Without a list file or data directory, the embedded list is used; a data
// directory list takes precedence.
func TestLoadPSLFallsBackToEmbeddedList(t *testing.T) {
	loader := &Loader{}
	if err := loader.LoadPSL(""); err != nil {
		t.Fatalf("LoadPSL without a list = %v", err)
	}
	if !loader.TLDRegistered("example.com") || !loader.IsPublicSuffix("github.io") || loader.IsICANNPublicSuffix("github.io") {
		t.Error("embedded list lacks com or the PRIVATE github.io")
	}
	if icann, private, _ := loader.Stats(); icann < 5000 || private < 1000 {
		t.Errorf("embedded list has %d ICANN and %d private rules", icann, private)
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
