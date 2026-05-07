package crl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	stdio "io"
	"net/http"
	"os"
	"time"

	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"

	fileio "github.com/cavoq/PCL/internal/io"
)

var extensions = []string{".crl", ".pem"}

type Format string

const (
	FormatDER Format = "DER" // RFC 5280 required format
	FormatPEM Format = "PEM" // Fallback format
)

type Info struct {
	CRL      *x509.RevocationList
	FilePath string
	Hash     string
	Source   source.Info
	Format   Format
}

func ParseCRL(data []byte) (*x509.RevocationList, error) {
	crl, _, err := parseCRL(data)
	return crl, err
}

func parseCRL(data []byte) (*x509.RevocationList, Format, error) {
	crl, err := x509.ParseRevocationList(data)
	if err == nil {
		return crl, FormatDER, nil
	}
	derErr := err

	block, _ := pem.Decode(data)
	if block != nil && block.Type == "X509 CRL" {
		crl, err = x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PEM CRL: %w", err)
		}
		return crl, FormatPEM, nil
	}

	return nil, "", fmt.Errorf("failed to parse PEM or DER CRL: %w", derErr)
}

func GetCRLFiles(path string) ([]string, error) {
	return fileio.GetFilesWithExtensions(path, extensions...)
}

func GetCRLs(path string) ([]*Info, error) {
	files, err := GetCRLFiles(path)
	if err != nil {
		return nil, err
	}

	infos := make([]*Info, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		crl, format, err := parseCRL(data)
		if err != nil {
			continue
		}

		hash := sha256.Sum256(crl.Raw)
		infos = append(infos, &Info{
			CRL:      crl,
			FilePath: file,
			Hash:     hex.EncodeToString(hash[:]),
			Source:   source.Info{Type: source.Local, Format: string(format)},
			Format:   format,
		})
	}

	if len(infos) == 0 && len(files) > 0 {
		return nil, fmt.Errorf("no valid items found in %s", path)
	}

	return infos, nil
}

func FetchCRL(url string, timeout time.Duration) (*Info, error) {
	if url == "" {
		return nil, fmt.Errorf("CRL URL is required")
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRL from %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned status %d", resp.StatusCode)
	}

	body, err := stdio.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response: %w", err)
	}

	crl, format, err := parseCRL(body)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(crl.Raw)
	return &Info{
		CRL:      crl,
		FilePath: url,
		Hash:     hex.EncodeToString(hash[:]),
		Source:   source.Info{Type: source.Downloaded, URL: url, Format: string(format)},
		Format:   format,
	}, nil
}

func FetchCRLs(urls []string, timeout time.Duration) ([]*Info, []error) {
	var results []*Info
	var errs []error

	for _, url := range urls {
		result, err := FetchCRL(url, timeout)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, result)
	}

	return results, errs
}
