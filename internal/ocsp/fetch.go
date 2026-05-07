package ocsp

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

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

func postOCSPRequest(url string, req []byte, timeout time.Duration) (*ocsp.Response, error) {
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")

	client := &http.Client{Timeout: timeout}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send OCSP request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP server returned status %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	resp, err := ocsp.ParseResponse(body, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}
	return resp, nil
}
