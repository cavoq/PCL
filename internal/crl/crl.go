// Package crl provides CRL data types and properties.
package crl

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
)

var extensions = []string{".crl", ".pem"}

type Info struct {
	CRL      *x509.RevocationList
	FilePath string
	Hash     string
	Source   source.Info
	// Origins contains every acquisition URL known to have returned this CRL.
	// It is empty for local inputs. FetchSession snapshots preserve all origins
	// known when that result is returned.
	Origins []string
}

// ParseCRL parses a single DER or PEM CRL.
func ParseCRL(data []byte) (*x509.RevocationList, error) {
	crl, _, err := parseCRL(data)
	return crl, err
}

func parseCRL(data []byte) (*x509.RevocationList, source.Format, error) {
	lists, format, err := parseCRLs(data)
	if err != nil {
		return nil, "", err
	}
	if len(lists) != 1 {
		return nil, "", fmt.Errorf("expected one CRL, found %d", len(lists))
	}
	return lists[0], format, nil
}

// parseCRLs parses a DER CRL or every X509 CRL block of PEM data.
func parseCRLs(data []byte) ([]*x509.RevocationList, source.Format, error) {
	return source.DecodePEMOrDER(data, "X509 CRL", x509.ParseRevocationList)
}

// GetCRLs loads the CRLs of a file, or of every CRL file in a directory.
// Directory files that cannot be read or parsed are reported to w and
// skipped; the load fails when no file yields a CRL.
func GetCRLs(path string, w io.Writer) ([]*Info, error) {
	loaded, err := source.LoadFiles(path, extensions, parseCRLs, w)
	if err != nil {
		return nil, err
	}
	infos := make([]*Info, 0, len(loaded))
	for _, list := range loaded {
		infos = append(infos, &Info{
			CRL:      list.Item,
			FilePath: list.Path,
			Hash:     crlHash(list.Item),
			Source:   source.Info{Type: source.Local, Format: list.Format},
		})
	}
	return infos, nil
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
