package ocsp

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/httpfetch"
	"github.com/cavoq/PCL/internal/x509node"
	"golang.org/x/crypto/ocsp"
)

// FetchOCSP sends an OCSP request and returns the response with source/request metadata.
func FetchOCSP(cert, issuer *x509.Certificate, url string, timeout time.Duration, nonceOpts *NonceOptions) (*Info, error) {
	if err := validateOCSPFetchInput(cert, issuer, url); err != nil {
		return nil, err
	}

	req, reqInfo, err := buildOCSPRequest(cert, issuer, nonceOpts)
	if err != nil {
		return nil, err
	}

	resp, err := postOCSPRequest(url, req, timeout)
	if err != nil {
		return nil, err
	}

	return infoFromDownloadedResponse(resp, reqInfo, url), nil
}

func validateOCSPFetchInput(cert, issuer *x509.Certificate, url string) error {
	if cert == nil {
		return fmt.Errorf("certificate is required")
	}
	if issuer == nil {
		return fmt.Errorf("issuer certificate is required for OCSP request")
	}
	if url == "" {
		return fmt.Errorf("OCSP URL is required")
	}
	return nil
}

// maxOCSPResponseBytes bounds a downloaded OCSP response. Responses are a
// few kilobytes; the limit leaves room for embedded responder chains.
const maxOCSPResponseBytes = 1 << 20

func postOCSPRequest(url string, req []byte, timeout time.Duration) (*ocsp.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	body, err := httpfetch.Client{}.Post(
		ctx, url, "application/ocsp-request", "application/ocsp-response", req, maxOCSPResponseBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("OCSP request to %s failed: %w", url, err)
	}

	resp, err := ocsp.ParseResponse(body, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}
	return resp, nil
}

func FetchForChain(chain []*cert.Info, timeout time.Duration, nonceOpts *NonceOptions) ([]*Info, []error) {
	var results []*Info
	var errs []error

	for i := 0; i < len(chain)-1; i++ {
		c := chain[i]
		if c.Cert == nil || len(c.Cert.OCSPServer) == 0 {
			continue
		}

		info, err := fetchForPair(c, chain[i+1], timeout, nonceOpts)
		if err != nil {
			errs = append(errs, fmt.Errorf("cert %d: %w", i, err))
			continue
		}
		if info != nil {
			results = append(results, info)
		}
	}

	return results, errs
}

func fetchForPair(c, issuer *cert.Info, timeout time.Duration, nonceOpts *NonceOptions) (*Info, error) {
	if issuer == nil || issuer.Cert == nil {
		return nil, fmt.Errorf("issuer certificate is required for OCSP request")
	}

	stdCert, err := x509node.ToStdCert(c.Cert)
	if err != nil {
		return nil, fmt.Errorf("failed to convert certificate to standard format: %w", err)
	}
	stdIssuer, err := x509node.ToStdCert(issuer.Cert)
	if err != nil {
		return nil, fmt.Errorf("failed to convert issuer certificate to standard format: %w", err)
	}

	url := ""
	if len(stdCert.OCSPServer) > 0 {
		url = stdCert.OCSPServer[0]
	}
	if url == "" {
		return nil, nil
	}

	info, err := FetchOCSP(stdCert, stdIssuer, url, timeout, nonceOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OCSP from %s: %w", url, err)
	}
	return info, nil
}
