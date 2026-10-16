package aia

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cavoq/PCL/internal/httpfetch"
	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
)

// IssuerResult contains certificates fetched from a CA Issuers URL.
type IssuerResult struct {
	Certs  []*x509.Certificate
	Source source.Info
}

// maxCAIssuersResponseBytes bounds a downloaded certificate or PKCS#7
// bundle from a CA Issuers URL.
const maxCAIssuersResponseBytes = 1 << 20

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

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	body, err := httpfetch.Client{}.Get(ctx, url, maxCAIssuersResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CA Issuers from %s: %w", url, err)
	}

	certs, format, err := ParseIssuerResponse(body)
	if err != nil {
		return nil, err
	}

	return issuerResult(certs, url, format), nil
}

// FetchCAIssuers fetches every HTTP(S) URL in urls. URLs with other
// schemes, such as ldap://, are skipped; when no URL is HTTP(S), it returns
// the single error from SupportedCAIssuersURLs.
func FetchCAIssuers(urls []string, timeout time.Duration) ([]*IssuerResult, []error) {
	supported, err := SupportedCAIssuersURLs(urls)
	if err != nil {
		return nil, []error{err}
	}

	var results []*IssuerResult
	var errs []error

	for _, url := range supported {
		result, err := FetchCAIssuer(url, timeout)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, result)
	}

	return results, errs
}

// SupportedCAIssuersURLs returns the HTTP(S) URLs of a certificate's CA
// Issuers access descriptions, the only ones PCL retrieves, as the CA/B
// Forum Baseline Requirements require for publicly-trusted certificates.
// It returns an error naming the other URLs when urls is non-empty and none
// is HTTP(S).
func SupportedCAIssuersURLs(urls []string) ([]string, error) {
	var supported []string
	var schemes []string
	for _, rawURL := range urls {
		scheme := urlScheme(rawURL)
		if scheme == "http" || scheme == "https" {
			supported = append(supported, rawURL)
			continue
		}
		if scheme != "" && !slices.Contains(schemes, scheme) {
			schemes = append(schemes, scheme)
		}
	}
	if len(supported) > 0 || len(urls) == 0 {
		return supported, nil
	}

	labels := make([]string, len(schemes))
	for index, scheme := range schemes {
		labels[index] = scheme + "://"
	}
	if len(labels) == 0 {
		labels = []string{"non-HTTP(S)"}
	}
	return nil, fmt.Errorf(
		"only %s CA Issuers URLs (%s); %s retrieval is not supported",
		strings.Join(labels, ", "),
		strings.Join(urls, ", "),
		unsupportedProtocols(schemes),
	)
}

func urlScheme(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Scheme)
}

func unsupportedProtocols(schemes []string) string {
	if len(schemes) == 0 {
		return "non-HTTP(S)"
	}
	protocols := make([]string, len(schemes))
	for index, scheme := range schemes {
		protocols[index] = strings.ToUpper(scheme)
	}
	return strings.Join(protocols, " and ")
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
