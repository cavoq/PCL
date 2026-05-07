// Package data provides external data loading for PCL.
//
// Currently supports:
//   - Public Suffix List (PSL) from publicsuffix.org
//   - IANA Root Zone Database TLD list
//
// Data files can be updated via:
//   pcl --update-data
package data

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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

// LoadPSL loads the Public Suffix List from file.
// If file doesn't exist, returns error (caller should handle fallback).
func (l *Loader) LoadPSL(filename string) error {
	l.pslMutex.Lock()
	defer l.pslMutex.Unlock()

	// Resolve file path
	var filePath string
	if filename != "" {
		filePath = filename
	} else if l.dataDir != "" {
		filePath = filepath.Join(l.dataDir, "public_suffix_list.dat")
	} else {
		return fmt.Errorf("no PSL file specified and no data directory found")
	}

	// Check file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("PSL file not found: %s", filePath)
	}

	// Parse file
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
//   // ===BEGIN ICANN DOMAINS===
//   com
//   net
//   ...
//   // ===END ICANN DOMAINS===
//   // ===BEGIN PRIVATE DOMAINS===
//   github.io
//   ...
//   // ===END PRIVATE DOMAINS===
func parsePSLFile(filePath string) (*PSL, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	psl := &PSL{
		ICANNDomains:      make(map[string]bool),
		PrivateDomains:    make(map[string]bool),
		AllPublicSuffixes: make(map[string]bool),
	}

	scanner := bufio.NewScanner(file)
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

// GetPSL returns the loaded PSL, or nil if not loaded.
func (l *Loader) GetPSL() *PSL {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()
	return l.psl
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

// IsICANNDomain checks if a domain is in ICANN section (official TLD).
func (l *Loader) IsICANNDomain(domain string) bool {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()

	if l.psl == nil {
		return false
	}

	return l.psl.ICANNDomains[domain]
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

// Stats returns statistics about the loaded PSL.
func (l *Loader) Stats() (icann, private int, loaded bool) {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()

	if l.psl == nil {
		return 0, 0, false
	}

	return len(l.psl.ICANNDomains), len(l.psl.PrivateDomains), true
}

// DownloadPSL downloads the Public Suffix List from publicsuffix.org.
func DownloadPSL(url string, destPath string) error {
	if url == "" {
		url = "https://publicsuffix.org/list/public_suffix_list.dat"
	}

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download PSL: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download PSL: HTTP %d", resp.StatusCode)
	}

	// Ensure destination directory exists
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to file
	file, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() { _ = file.Close() }()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
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