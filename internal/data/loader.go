// Package data provides external data loading for PCL: the Public Suffix
// List from publicsuffix.org, whose ICANN section also serves as the list of
// registered top-level domains.
//
// The list compiled into github.com/weppos/publicsuffix-go is used when no
// list file is found; a newer list can be downloaded with:
//
//	pcl update-data
package data

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/weppos/publicsuffix-go/publicsuffix"

	"github.com/cavoq/PCL/internal/httpfetch"
)

// PSL is a loaded Public Suffix List.
type PSL struct {
	list *publicsuffix.List
	// tlds holds the top-level labels of the ICANN section's rules, in
	// lowercase A-label form.
	tlds           map[string]bool
	icann, private int
}

func newPSL(list *publicsuffix.List, rules []publicsuffix.Rule) *PSL {
	psl := &PSL{list: list, tlds: make(map[string]bool)}
	for _, rule := range rules {
		if rule.Private {
			psl.private++
			continue
		}
		psl.icann++
		if rule.Value != "" {
			psl.tlds[rule.Value[strings.LastIndexByte(rule.Value, '.')+1:]] = true
		}
	}
	return psl
}

// isPublicSuffix applies the list's algorithm, with its wildcard and
// exception rules and the implicit "*" rule, to domain in A-label form;
// case and a trailing dot are ignored.
func (psl *PSL) isPublicSuffix(domain string, ignorePrivate bool) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" {
		return false
	}
	rule := psl.list.Find(domain, &publicsuffix.FindOptions{
		IgnorePrivate: ignorePrivate,
		DefaultRule:   publicsuffix.DefaultRule,
	})
	// Decompose leaves no suffix when domain is all suffix.
	return rule.Decompose(domain)[1] == ""
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

	// 3. Fallback: return empty (will use the embedded list)
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

// ErrPSLNotFound reports that no Public Suffix List file was found.
var ErrPSLNotFound = errors.New("no Public Suffix List file found")

// LoadPSL loads the Public Suffix List from filename, or from the data
// directory when filename is empty, or else the list compiled into the
// binary. A missing filename is reported as ErrPSLNotFound.
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
		rules := publicsuffix.DefaultRules()
		l.psl = newPSL(publicsuffix.DefaultList, rules[:])
		return nil
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrPSLNotFound, filePath)
	}

	list := publicsuffix.NewList()
	rules, err := list.LoadFile(filePath, &publicsuffix.ParserOption{PrivateDomains: true})
	if err != nil {
		return fmt.Errorf("failed to parse PSL file: %w", err)
	}
	l.psl = newPSL(list, rules)
	return nil
}

// IsPublicSuffix reports whether domain is a public suffix under the ICANN
// or PRIVATE section of the list, applying its wildcard and exception rules
// and the implicit "*" rule that makes every single label a public suffix.
// domain is a DNS name in A-label form; case and a trailing dot are ignored.
// It is false when no list is loaded.
func (l *Loader) IsPublicSuffix(domain string) bool {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()
	return l.psl != nil && l.psl.isPublicSuffix(domain, false)
}

// IsICANNPublicSuffix is IsPublicSuffix without the PRIVATE section
// (CA/B Forum BR 3.2.2.6).
func (l *Loader) IsICANNPublicSuffix(domain string) bool {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()
	return l.psl != nil && l.psl.isPublicSuffix(domain, true)
}

// TLDRegistered reports whether the top-level label of domain, in A-label
// form, is the last label of an ICANN section rule, as every top-level
// domain of the IANA Root Zone is. Case and a trailing dot are ignored. It
// is false when no list is loaded.
func (l *Loader) TLDRegistered(domain string) bool {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()

	if l.psl == nil {
		return false
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	return l.psl.tlds[domain[strings.LastIndexByte(domain, '.')+1:]]
}

// Loaded reports whether a Public Suffix List is loaded.
func (l *Loader) Loaded() bool {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()
	return l.psl != nil
}

// Stats returns the number of ICANN and PRIVATE rules of the loaded list.
func (l *Loader) Stats() (icann, private int, loaded bool) {
	l.pslMutex.RLock()
	defer l.pslMutex.RUnlock()

	if l.psl == nil {
		return 0, 0, false
	}

	return l.psl.icann, l.psl.private, true
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
	fmt.Printf("Successfully loaded PSL: %d ICANN rules, %d private rules\n", icann, private)

	return nil
}
