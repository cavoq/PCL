// Package crl provides CRL data types and properties.
package crl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cavoq/PCL/internal/fsutil"
	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
)

var extensions = []string{".crl", ".pem"}

type Info struct {
	CRL      *x509.RevocationList
	FilePath string
	Hash     string
	Source   source.Info
	Format   source.Format
	// Origins contains every acquisition URL known to have returned this CRL.
	// It is empty for local inputs. FetchSession snapshots preserve all origins
	// known when that result is returned.
	Origins []string
}

func ParseCRL(data []byte) (*x509.RevocationList, error) {
	crl, _, err := parseCRL(data)
	return crl, err
}

func parseCRL(data []byte) (*x509.RevocationList, source.Format, error) {
	crl, err := x509.ParseRevocationList(data)
	if err == nil {
		return crl, source.FormatDER, nil
	}
	derErr := err

	block, _ := pem.Decode(data)
	if block != nil && block.Type == "X509 CRL" {
		crl, err = x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PEM CRL: %w", err)
		}
		return crl, source.FormatPEM, nil
	}

	return nil, "", fmt.Errorf("failed to parse PEM or DER CRL: %w", derErr)
}

func GetCRLFiles(path string) ([]string, error) {
	return fsutil.GetFilesWithExtensions(path, extensions...)
}

// GetCRLs loads the CRL of a file, or of every CRL file in a directory.
// Directory files that cannot be read or parsed are reported to w and
// skipped; the load fails when no file yields a CRL.
func GetCRLs(path string, w io.Writer) ([]*Info, error) {
	files, err := GetCRLFiles(path)
	if err != nil {
		return nil, err
	}

	infos := make([]*Info, 0, len(files))
	var skipped []error
	for _, file := range files {
		crl, format, err := loadCRLFile(file)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("%s: %w", file, err))
			continue
		}
		infos = append(infos, &Info{
			CRL:      crl,
			FilePath: file,
			Hash:     crlHash(crl),
			Source:   source.Info{Type: source.Local, Format: format},
			Format:   format,
		})
	}

	if len(infos) == 0 && len(skipped) > 0 {
		return nil, fmt.Errorf("no valid items found in %s: %w", path, skipped[0])
	}
	fsutil.ReportSkipped(w, skipped)
	return infos, nil
}

func loadCRLFile(file string) (*x509.RevocationList, source.Format, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, "", err
	}
	return parseCRL(data)
}

func crlHash(revocationList *x509.RevocationList) string {
	if revocationList == nil {
		return ""
	}
	hash := sha256.Sum256(revocationList.Raw)
	return hex.EncodeToString(hash[:])
}

func FetchCRL(url string, timeout time.Duration) (*Info, error) {
	return newFetchSession(FetchConfig{Timeout: timeout}, true).Fetch(url)
}
