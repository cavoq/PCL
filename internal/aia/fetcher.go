package aia

import (
	certstd "crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"

	zcryptoconv "github.com/cavoq/PCL/internal/zcrypto"
)

// PKCS#7 OIDs
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2} // id-signedData (1.2.840.113549.1.7.2)

// Result contains the fetched certificate and format information.
type Result struct {
	Cert   *x509.Certificate
	Format source.Format
	URL    string
}

// PKCS7Result contains multiple certificates from a PKCS#7 bundle.
type PKCS7Result struct {
	Certs  []*x509.Certificate
	Format source.Format
	URL    string
}

// FetchCAIssuer downloads and parses a certificate from a CA Issuers URL.
// Per RFC 5280 Section 4.2.2.1, the CA Issuers URL must point to:
//   - Single DER-encoded certificate, OR
//   - BER/DER-encoded PKCS#7 certs-only bundle
//
// Returns zcrypto certificate for consistency with the rest of the codebase.
func FetchCAIssuer(url string, timeout time.Duration) (*Result, error) {
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

	// Try DER format first (single DER-encoded certificate per RFC 5280)
	cert, err := x509.ParseCertificate(body)
	if err == nil {
		return &Result{Cert: cert, Format: source.FormatDER, URL: url}, nil
	}

	// Try PKCS#7 SignedData format (certs-only bundle per RFC 5280)
	pkcs7Certs, err := parsePKCS7CertsOnly(body)
	if err == nil && len(pkcs7Certs) > 0 {
		// Return the first certificate (typically the issuer certificate)
		// Caller can use FetchCAIssuerPKCS7 to get all certificates if needed
		return &Result{Cert: pkcs7Certs[0], Format: source.FormatPKCS7, URL: url}, nil
	}

	// Try PEM format as fallback (non-compliant but commonly used)
	block, _ := pem.Decode(body)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM certificate from CA Issuers: %w", err)
		}
		return &Result{Cert: cert, Format: source.FormatPEM, URL: url}, nil
	}

	return nil, fmt.Errorf("failed to parse CA Issuers: expected DER certificate, PKCS#7 bundle, or PEM format")
}

// FetchCAIssuerPKCS7 downloads and parses certificates from a CA Issuers URL,
// returning all certificates if the response is a PKCS#7 bundle.
// Useful when the PKCS#7 bundle contains multiple certificates (e.g., chain).
func FetchCAIssuerPKCS7(url string, timeout time.Duration) (*PKCS7Result, error) {
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

	// Try DER format first (single certificate)
	cert, err := x509.ParseCertificate(body)
	if err == nil {
		return &PKCS7Result{Certs: []*x509.Certificate{cert}, Format: source.FormatDER, URL: url}, nil
	}

	// Try PKCS#7 format (certificate bundle)
	pkcs7Certs, err := parsePKCS7CertsOnly(body)
	if err == nil && len(pkcs7Certs) > 0 {
		return &PKCS7Result{Certs: pkcs7Certs, Format: source.FormatPKCS7, URL: url}, nil
	}

	// Try PEM format
	block, _ := pem.Decode(body)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM certificate from CA Issuers: %w", err)
		}
		return &PKCS7Result{Certs: []*x509.Certificate{cert}, Format: source.FormatPEM, URL: url}, nil
	}

	return nil, fmt.Errorf("failed to parse CA Issuers: expected DER certificate, PKCS#7 bundle, or PEM format")
}

// FetchCAIssuers downloads certificates from multiple CA Issuer URLs.
// Returns results and any errors encountered.
// Network failures are returned as errors, not as policy failures.
func FetchCAIssuers(urls []string, timeout time.Duration) ([]*Result, []error) {
	var results []*Result
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

// ToStdCert converts zcrypto certificate to standard Go certificate.
func ToStdCert(cert *x509.Certificate) (*certstd.Certificate, error) {
	return zcryptoconv.ToStdCert(cert)
}

// parsePKCS7CertsOnly parses a PKCS#7 SignedData structure and extracts certificates.
// PKCS#7 SignedData (certs-only) structure per RFC 5652:
//
//	ContentInfo ::= SEQUENCE {
//	  contentType ContentType,  -- OID: 1.2.840.113549.1.7.2 for signedData
//	  content [0] EXPLICIT ANY DEFINED BY contentType
//	}
//	SignedData ::= SEQUENCE {
//	  version INTEGER,
//	  digestAlgorithms SET,
//	  encapContentInfo SEQUENCE,
//	  certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
//	  signerInfos SET
//	}
func parsePKCS7CertsOnly(data []byte) ([]*x509.Certificate, error) {
	// Parse ContentInfo
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(data, &contentInfo); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 ContentInfo: %w", err)
	}

	// Verify it's signedData (1.2.840.113549.1.7.2)
	if !contentInfo.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("PKCS#7 contentType is not signedData: %v", contentInfo.ContentType)
	}

	// Parse SignedData from Content.Bytes (strips explicit tag wrapper)
	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo struct {
			ContentType asn1.ObjectIdentifier
			Content     asn1.RawValue `asn1:"optional,explicit,tag:0"`
		}
		Certificates asn1.RawValue `asn1:"optional,implicit,tag:0"`
		CRLs         asn1.RawValue `asn1:"optional,implicit,tag:1"`
		SignerInfos  asn1.RawValue
	}
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 SignedData: %w", err)
	}

	// Extract certificates from the [0] IMPLICIT SET OF Certificate
	// Due to implicit tagging, the tag is replaced from SET (17) to context-specific [0]
	// FullBytes contains the complete tagged content, Bytes contains inner SET data
	if len(signedData.Certificates.Bytes) == 0 {
		return nil, fmt.Errorf("PKCS#7 SignedData contains no certificates")
	}

	certs, err := parseCertificateSet(signedData.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 certificates: %w", err)
	}

	return certs, nil
}

// parseCertificateSet parses a SET OF Certificate bytes and returns zcrypto certificates.
func parseCertificateSet(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// Parse the SET content directly
	remaining := data
	for len(remaining) > 0 {
		// Each element in the SET is a SEQUENCE (Certificate)
		var certRaw asn1.RawValue
		n, err := asn1.Unmarshal(remaining, &certRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate element: %w", err)
		}

		// Parse the certificate DER bytes
		cert, err := x509.ParseCertificate(certRaw.FullBytes)
		if err != nil {
			// Try standard library parser as fallback
			stdCert, stdErr := certstd.ParseCertificate(certRaw.FullBytes)
			if stdErr != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			// Convert std cert to zcrypto cert
			cert, err = zcryptoconv.FromStdCert(stdCert)
			if err != nil {
				return nil, fmt.Errorf("failed to convert certificate: %w", err)
			}
		}

		certs = append(certs, cert)
		remaining = n
	}

	return certs, nil
}
