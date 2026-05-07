package aia

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
)

// IssuerResult contains certificates fetched from a CA Issuers URL.
type IssuerResult struct {
	Certs  []*x509.Certificate
	Source source.Info
}

// FetchCAIssuer downloads and parses a certificate from a CA Issuers URL.
// Per RFC 5280 Section 4.2.2.1, the CA Issuers URL must point to:
//   - Single DER-encoded certificate, OR
//   - BER/DER-encoded PKCS#7 certs-only bundle
//
// Returns zcrypto certificate for consistency with the rest of the codebase.
func FetchCAIssuer(url string, timeout time.Duration) (*IssuerResult, error) {
	if url == "" {
		return nil, fmt.Errorf("CA Issuers URL is required")
	}

	client := &http.Client{
		Timeout: timeout,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CA Issuers from %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CA Issuers server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA Issuers response: %w", err)
	}

	certs, format, err := ParseIssuerResponse(body)
	if err != nil {
		return nil, err
	}

	return issuerResult(certs, url, format), nil
}

func FetchCAIssuers(urls []string, timeout time.Duration) ([]*IssuerResult, []error) {
	var results []*IssuerResult
	var errs []error

	for _, url := range urls {
		result, err := FetchCAIssuer(url, timeout)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, result)
	}

	return results, errs
}

func issuerResult(certs []*x509.Certificate, url string, format source.Format) *IssuerResult {
	return &IssuerResult{
		Certs: certs,
		Source: source.Info{
			Type:   source.Downloaded,
			URL:    url,
			Format: format,
		},
	}
}
