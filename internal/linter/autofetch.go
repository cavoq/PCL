package linter

import (
	certstd "crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/aia"
	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/zcrypto"
	"github.com/zmap/zcrypto/x509"
)

// climbChain recursively fetches issuer certificates via CA Issuers URLs.
// Starts from the top of the chain and climbs toward root until:
// - Self-signed certificate found (root)
// - Max depth reached
// - No CA Issuers URL found
// - Circular certificate detected
//
// Handles PKCS#7 bundles: extracts all certificates and selects the correct issuer
// by matching Issuer DN and/or AKI extension.
func climbChain(chain []*cert.Info, timeout time.Duration, maxDepth int, w io.Writer) []*cert.Info {
	if len(chain) == 0 || maxDepth <= 0 {
		return chain
	}

	// Track seen certificates to detect circular chains
	seen := make(map[string]bool)
	for _, c := range chain {
		if c.Cert != nil && c.Cert.SerialNumber != nil {
			seen[c.Cert.SerialNumber.String()] = true
		}
	}

	result := chain
	depth := 0

	for depth < maxDepth {
		// Get the highest certificate in the chain (potential issuer to climb)
		top := result[len(result)-1]
		if top.Cert == nil {
			break
		}

		// Check if it's self-signed (root)
		if top.Cert.Issuer.String() == top.Cert.Subject.String() {
			break
		}

		// Check for CA Issuers URL
		if len(top.Cert.IssuingCertificateURL) == 0 {
			break
		}

		// Fetch issuer(s) from first CA Issuers URL (may be PKCS#7 bundle)
		url := top.Cert.IssuingCertificateURL[0]
		pkcs7Result, err := aia.FetchCAIssuerPKCS7(url, timeout)
		if err != nil {
			_, _ = fmt.Fprintf(w, "Warning: failed to climb chain from %s: %v\n", url, err)
			break
		}

		// Find the correct issuer certificate from the bundle
		// Match by Issuer DN (subject of issuer should match issuer of cert)
		var issuerCert *x509.Certificate
		for _, cert := range pkcs7Result.Certs {
			// Check if this cert's subject matches the current cert's issuer
			if cert.Subject.String() == top.Cert.Issuer.String() {
				issuerCert = cert
				break
			}
		}

		// If no exact DN match, try AKI-SKI matching
		if issuerCert == nil && len(top.Cert.AuthorityKeyId) > 0 {
			for _, cert := range pkcs7Result.Certs {
				if len(cert.SubjectKeyId) > 0 && string(cert.SubjectKeyId) == string(top.Cert.AuthorityKeyId) {
					issuerCert = cert
					break
				}
			}
		}

		// Fallback: use first certificate if only one, or continue with best guess
		if issuerCert == nil {
			if len(pkcs7Result.Certs) == 1 {
				issuerCert = pkcs7Result.Certs[0]
			} else {
				// Multiple certs with no match - use first as best guess
				issuerCert = pkcs7Result.Certs[0]
				_, _ = fmt.Fprintf(w, "Warning: PKCS#7 bundle contains %d certs, no exact issuer match found, using first cert\n", len(pkcs7Result.Certs))
			}
		}

		// Check for circular certificate
		if issuerCert.SerialNumber != nil {
			serial := issuerCert.SerialNumber.String()
			if seen[serial] {
				_, _ = fmt.Fprintf(w, "Warning: circular certificate detected at %s\n", url)
				break
			}
			seen[serial] = true
		}

		// Add issuer to chain
		sourceInfo := source.Info{
			Type:   source.Downloaded,
			URL:    url,
			Format: string(pkcs7Result.Format),
		}
		switch pkcs7Result.Format {
		case aia.FormatPKCS7:
			sourceInfo.Type = source.Extracted
			sourceInfo.Description = "extracted from PKCS#7"
		case aia.FormatDER:
		case aia.FormatPEM:
			sourceInfo.Description = "downloaded PEM"
			_, _ = fmt.Fprintf(w, "Warning: CA Issuers URL %s returned PEM format (RFC 5280 requires DER/BER)\n", url)
		}
		issuerInfo := &cert.Info{
			Cert:     issuerCert,
			FilePath: url,
			Type:     cert.GetCertType(issuerCert, len(result), len(result)+1),
			Position: len(result),
			Source:   sourceInfo,
			Format:   cert.Format(pkcs7Result.Format),
		}
		result = append(result, issuerInfo)

		depth++
	}

	// Rebuild chain types after climbing is complete
	for i, c := range result {
		c.Position = i
		c.Type = cert.GetCertType(c.Cert, i, len(result))
	}

	return result
}

// fetchAutoCRL fetches CRLs from CRL Distribution Points for certificates in chain.
func fetchAutoCRL(chain []*cert.Info, timeout time.Duration, w io.Writer) []*crl.Info {
	var results []*crl.Info

	for _, c := range chain {
		if c.Cert == nil || len(c.Cert.CRLDistributionPoints) == 0 {
			continue
		}

		for _, url := range c.Cert.CRLDistributionPoints {
			fetchResult, err := crl.FetchCRL(url, timeout)
			if err != nil {
				_, _ = fmt.Fprintf(w, "Warning: failed to fetch CRL from %s: %v\n", url, err)
				continue
			}

			results = append(results, fetchResult)
		}
	}

	return results
}

// fetchAutoOCSP automatically fetches OCSP responses for certificates in the chain.
// For leaf certificates, uses the OCSP URL from AIA extension and issuer from chain.
func fetchAutoOCSP(chain []*cert.Info, timeout time.Duration, nonceOpts *ocsp.NonceOptions) ([]*ocsp.Info, error) {
	if len(chain) < 2 {
		return nil, fmt.Errorf("chain must have at least 2 certificates for OCSP request")
	}

	results := make([]*ocsp.Info, 0, 1)

	// Convert zcrypto certs to standard certs for OCSP request
	stdChain := make([]*certstd.Certificate, 0, len(chain))
	for _, c := range chain {
		if c.Cert == nil {
			continue
		}
		stdCert, err := zcrypto.ToStdCert(c.Cert)
		if err != nil {
			continue
		}
		stdChain = append(stdChain, stdCert)
	}

	if len(stdChain) < 2 {
		return nil, fmt.Errorf("failed to convert certificates to standard format")
	}

	// Fetch OCSP for leaf certificate
	fetchResult, url, err := ocsp.FetchOCSPFromChainWithInfo(stdChain, timeout, nonceOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OCSP from %s: %w", url, err)
	}
	if fetchResult == nil {
		// No OCSP URL in certificate, not an error
		return nil, nil
	}

	info := &ocsp.Info{
		Response: fetchResult.Response,
		FilePath: url, // Use URL as "file path" for auto-fetched responses
		Source:   "downloaded",
	}

	// Populate request debug info
	if fetchResult.RequestInfo != nil {
		info.RequestNonce = fetchResult.RequestInfo.Nonce
		info.RequestNonceHex = fetchResult.RequestInfo.NonceHex
		info.RequestNonceLen = fetchResult.RequestInfo.NonceLen
		info.RequestRawLen = fetchResult.RequestInfo.RequestLen
		info.RequestHashAlgorithm = fetchResult.RequestInfo.HashAlgorithm
	}

	results = append(results, info)

	return results, nil
}
