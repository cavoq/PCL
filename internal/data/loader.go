// Package data provides external data loading for PCL: the Public Suffix
// List from publicsuffix.org, whose ICANN section also serves as the list of
// registered top-level domains.
//
// A snapshot of the list is embedded and used when no list file is found;
// a newer list can be downloaded with:
//
//	pcl update-data
package data

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"

	"github.com/cavoq/PCL/internal/httpfetch"
)

// PSL represents the Public Suffix List loaded from external file.
// It contains both ICANN domains (official TLDs) and PRIVATE domains.
type PSL struct {
	// ICANN domains - official TLDs from IANA Root Zone Database
	ICANNDomains map[string]bool

	// Private domains - additional public suffixes (e.g., github.io)
	PrivateDomains map[string]bool

	// All public suffixes (ICANN + Private combined)
	AllPublicSuffixes map[string]bool

	// icannRules holds the ICANN section's rules in lowercase A-label form,
	// including wildcard ("*.ck") and exception ("!www.ck") rules.
	icannRules map[string]bool

	// Metadata
	LoadedAt   time.Time
	SourceFile string
}

// Loader manages external data file loading.
type Loader struct {
	psl      *PSL
	pslMutex sync.RWMutex

	// Default data directory
	dataDir string
}

// DefaultLoader is the global loader instance.
var DefaultLoader = &Loader{
	dataDir: getDefaultDataDir(),
}

// getDefaultDataDir returns the default directory for data files.
// Checks: ./data, ~/.pcl/data, then falls back to embedded.
func getDefaultDataDir() string {
	// 1. Current working directory ./data
	if cwd, err := os.Getwd(); err == nil {
		dataPath := filepath.Join(cwd, "data")
		if _, err := os.Stat(dataPath); err == nil {
			return dataPath
		}
	}

	// 2. User home directory ~/.pcl/data
	if home, err := os.UserHomeDir(); err == nil {
		dataPath := filepath.Join(home, ".pcl", "data")
		if _, err := os.Stat(dataPath); err == nil {
			return dataPath
		}
	}

	// 3. Fallback: return empty (will use embedded/regex fallback)
	return ""
}

// SetDataDir overrides the directory searched for data files. An empty
// directory keeps the default lookup result.
func (l *Loader) SetDataDir(dir string) {
	if dir == "" {
		return
	}
	l.pslMutex.Lock()
	defer l.pslMutex.Unlock()
	l.dataDir = dir
}

// embeddedPSL is the Public Suffix List snapshot shipped in the binary,
// refreshed with `make psl-snapshot`.
//
//go:embed public_suffix_list.dat
var embeddedPSL []byte

// EmbeddedPSLVersion returns the VERSION header of the embedded snapshot.
func EmbeddedPSLVersion() string {
	for _, line := range strings.Split(string(embeddedPSL), "\n") {
		if version, found := strings.CutPrefix(line, "// VERSION: "); found {
			return strings.TrimSpace(version)
		}
	}
	return "unknown"
}

// ErrPSLNotFound reports that no Public Suffix List file was found.
var ErrPSLNotFound = errors.New("no Public Suffix List file found")

// LoadPSL loads the Public Suffix List from filename, or from the data
// directory when filename is empty, or else from the embedded snapshot. A
// missing filename is reported as ErrPSLNotFound.
func (l *Loader) LoadPSL(filename string) error {
	l.pslMutex.Lock()
	defer l.pslMutex.Unlock()

	filePath := filename
	if filePath == "" && l.dataDir != "" {
		filePath = filepath.Join(l.dataDir, "public_suffix_list.dat")
		if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
			filePath = ""
		}
	}
	if filePath == "" {
		psl, err := parsePSL(bytes.NewReader(embeddedPSL))
		if err != nil {
			return fmt.Errorf("failed to parse embedded PSL snapshot: %w", err)
		}
		psl.SourceFile = "embedded snapshot " + EmbeddedPSLVersion()
		psl.LoadedAt = time.Now()
		l.psl = psl
		return nil
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrPSLNotFound, filePath)
	}

	psl, err := parsePSLFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to parse PSL file: %w", err)
	}

	psl.SourceFile = filePath
	psl.LoadedAt = time.Now()
	l.psl = psl

	return nil
}

// parsePSLFile parses the Public Suffix List file format.
//
// Format (from publicsuffix.org):
//
//	// ===BEGIN ICANN DOMAINS===
//	com
//	net
//	...
//	// ===END ICANN DOMAINS===
//	// ===BEGIN PRIVATE DOMAINS===
//	github.io
//	...
//	// ===END PRIVATE DOMAINS===
func parsePSLFile(filePath string) (*PSL, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return parsePSL(file)
}

func parsePSL(input io.Reader) (*PSL, error) {
	psl := &PSL{
		ICANNDomains:      make(map[string]bool),
		PrivateDomains:    make(map[string]bool),
		AllPublicSuffixes: make(map[string]bool),
		icannRules:        make(map[string]bool),
	}

	scanner := bufio.NewScanner(input)
	var section string // "icann", "private", or ""

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Detect section markers
		if strings.Contains(line, "BEGIN ICANN DOMAINS") {
			section = "icann"
			continue
		}
		if strings.Contains(line, "END ICANN DOMAINS") {
			section = ""
			continue
		}
		if strings.Contains(line, "BEGIN PRIVATE DOMAINS") {
			section = "private"
			continue
		}
		if strings.Contains(line, "END PRIVATE DOMAINS") {
			section = ""
			continue
		}

		// Skip comments (lines starting with //)
		if strings.HasPrefix(line, "//") {
			continue
		}

		// Parse domain entry
		domain := strings.TrimSpace(line)
		if domain == "" {
			continue
		}

		// Add to appropriate section
		switch section {
		case "icann":
			psl.ICANNDomains[domain] = true
			psl.AllPublicSuffixes[domain] = true
			if rule, ok := asciiRule(domain); ok {
				psl.icannRules[rule] = true
			}
		case "private":
			psl.PrivateDomains[domain] = true
			psl.AllPublicSuffixes[domain] = true
		default:
			// Before any section marker - still valid entries
			// Treat as ICANN (early entries in file are TLDs)
			psl.ICANNDomains[domain] = true
			psl.AllPublicSuffixes[domain] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return psl, nil
}

// IsPublicSuffix checks if a domain is a public suffix.
// Uses loaded PSL if available, otherwise returns false.
func (l *Loader) IsPublicSuffix(domain string) bool {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()

	if l.psl == nil {
		return false
	}

	return l.psl.AllPublicSuffixes[domain]
}

// IsICANNPublicSuffix reports whether domain is a public suffix under the
// ICANN section of the list, applying its wildcard and exception rules and
// the implicit "*" rule that makes every single label a public suffix.
// domain is a DNS name in A-label form; case and a trailing dot are ignored.
// The PRIVATE section is not consulted (CA/B Forum BR 3.2.2.6).
func (l *Loader) IsICANNPublicSuffix(domain string) bool {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()

	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if l.psl == nil || domain == "" {
		return false
	}
	rules := l.psl.icannRules
	if rules["!"+domain] {
		return false
	}
	if rules[domain] {
		return true
	}
	dot := strings.IndexByte(domain, '.')
	if dot < 0 {
		return true
	}
	return rules["*."+domain[dot+1:]]
}

// asciiRule converts a list rule to lowercase A-label form, keeping its
// "*." or "!" prefix.
func asciiRule(rule string) (string, bool) {
	prefix := ""
	switch {
	case strings.HasPrefix(rule, "!"):
		prefix, rule = "!", rule[1:]
	case strings.HasPrefix(rule, "*."):
		prefix, rule = "*.", rule[2:]
	}
	ascii, err := idna.Lookup.ToASCII(rule)
	if err != nil {
		return "", false
	}
	return prefix + strings.ToLower(ascii), true
}

// TLDRegistered checks if a TLD is registered in IANA Root Zone.
// This checks the top-level label of the domain against ICANN domains.
func (l *Loader) TLDRegistered(domain string) bool {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()

	if l.psl == nil {
		return false
	}

	// Extract TLD (last label)
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return false
	}

	tld := labels[len(labels)-1]
	return l.psl.ICANNDomains[tld]
}

// Loaded reports whether a Public Suffix List is loaded.
func (l *Loader) Loaded() bool {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()
	return l.psl != nil
}

// Stats returns statistics about the loaded PSL.
func (l *Loader) Stats() (icann, private int, loaded bool) {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()

	if l.psl == nil {
		return 0, 0, false
	}

	return len(l.psl.ICANNDomains), len(l.psl.PrivateDomains), true
}

// pslDownloadTimeout bounds the whole Public Suffix List download.
const pslDownloadTimeout = time.Minute

// maxPSLBytes bounds the downloaded Public Suffix List, which is a few
// hundred kilobytes.
const maxPSLBytes = 16 << 20

// DownloadPSL downloads the Public Suffix List from publicsuffix.org. The
// file at destPath is replaced only after a complete download.
func DownloadPSL(url string, destPath string) error {
	if url == "" {
		url = "https://publicsuffix.org/list/public_suffix_list.dat"
	}

	ctx, cancel := context.WithTimeout(context.Background(), pslDownloadTimeout)
	defer cancel()
	body, err := httpfetch.Client{}.Get(ctx, url, maxPSLBytes)
	if err != nil {
		return fmt.Errorf("failed to download PSL: %w", err)
	}

	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return writeFileAtomically(destPath, body)
}

// writeFileAtomically writes data to a temporary file next to path and
// renames it over path, so readers never see a partial file.
func writeFileAtomically(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	tempPath := file.Name()
	defer func() { _ = os.Remove(tempPath) }()

	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to write file: %w", err)
	}
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to write file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to replace file: %w", err)
	}
	return nil
}

// UpdateData downloads and updates all external data files.
func UpdateData(dataDir string) error {
	if dataDir == "" {
		dataDir = getDefaultDataDir()
	}

	if dataDir == "" {
		// Create default data directory
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		dataDir = filepath.Join(home, ".pcl", "data")
	}

	// Download PSL
	pslPath := filepath.Join(dataDir, "public_suffix_list.dat")
	fmt.Printf("Downloading Public Suffix List to: %s\n", pslPath)
	if err := DownloadPSL("", pslPath); err != nil {
		return fmt.Errorf("failed to update PSL: %w", err)
	}

	// Load to verify
	if err := DefaultLoader.LoadPSL(pslPath); err != nil {
		return fmt.Errorf("failed to load downloaded PSL: %w", err)
	}

	icann, private, _ := DefaultLoader.Stats()
	fmt.Printf("Successfully loaded PSL: %d ICANN domains, %d private domains\n", icann, private)

	return nil
}
