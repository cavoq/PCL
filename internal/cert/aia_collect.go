package cert

import (
	"io"
	"time"

	"github.com/cavoq/PCL/internal/aia"
	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
)

// AIACollectConfig configures breadth-first CA Issuers collection.
type AIACollectConfig struct {
	Timeout  time.Duration
	MaxDepth int
	Warn     io.Writer
	// StopWhen, if set, stops after a discovered certificate satisfies the predicate.
	StopWhen func(*x509.Certificate) bool
}

// CollectViaCAIssuers walks CA Issuers URLs from seed certificates and returns
// the seed plus any newly discovered certificates (breadth-first, deduplicated by serial).
func CollectViaCAIssuers(seed []*x509.Certificate, cfg AIACollectConfig) []*x509.Certificate {
	pool := append([]*x509.Certificate(nil), seed...)
	if cfg.MaxDepth <= 0 || cfg.Timeout <= 0 {
		return pool
	}

	seen := serialSeenSet(pool)
	frontier := append([]*x509.Certificate(nil), seed...)

	for depth := 0; depth < cfg.MaxDepth; depth++ {
		var added []*x509.Certificate
		for _, c := range frontier {
			if c == nil {
				continue
			}
			newCerts, stop := discoverViaCAIssuers(c, seen, cfg)
			added = append(added, newCerts...)
			if stop {
				return append(pool, added...)
			}
		}
		if len(added) == 0 {
			break
		}
		pool = append(pool, added...)
		frontier = added
	}

	return pool
}

// FetchParentViaCAIssuers fetches the issuing certificate for child using the first
// CA Issuers URL, matching ClimbChain behavior.
func FetchParentViaCAIssuers(child *x509.Certificate, timeout time.Duration, w io.Writer) (*x509.Certificate, source.Info, string, error) {
	if child == nil || len(child.IssuingCertificateURL) == 0 {
		return nil, source.Info{}, "", nil
	}

	url := child.IssuingCertificateURL[0]
	results, errs := aia.FetchCAIssuers([]string{url}, timeout)
	if len(errs) > 0 {
		return nil, source.Info{}, url, errs[0]
	}
	if len(results) == 0 {
		return nil, source.Info{}, url, nil
	}

	issuerResult := results[0]
	warnPKCS7Bundle(w, child, issuerResult.Certs)
	warnPEMDownload(w, url, issuerResult.Source.Format)

	issuerCert, _ := aia.SelectIssuer(child, issuerResult.Certs)
	if issuerCert == nil {
		return nil, source.Info{}, url, nil
	}

	return issuerCert, normalizeIssuerSourceInfo(issuerResult.Source), url, nil
}

func discoverViaCAIssuers(c *x509.Certificate, seen map[string]bool, cfg AIACollectConfig) ([]*x509.Certificate, bool) {
	if c == nil || len(c.IssuingCertificateURL) == 0 {
		return nil, false
	}

	results, errs := aia.FetchCAIssuers(c.IssuingCertificateURL, cfg.Timeout)
	for _, err := range errs {
		warnf(cfg.Warn, "Warning: %v\n", err)
	}

	var added []*x509.Certificate
	for _, result := range results {
		if result == nil {
			continue
		}
		warnPEMDownload(cfg.Warn, result.Source.URL, result.Source.Format)

		var stop bool
		added, stop = appendUniqueCandidates(seen, added, result.Certs, cfg.StopWhen)
		if stop {
			return added, true
		}
	}

	return added, false
}

func appendUniqueCandidates(
	seen map[string]bool,
	into []*x509.Certificate,
	candidates []*x509.Certificate,
	stopWhen func(*x509.Certificate) bool,
) ([]*x509.Certificate, bool) {
	for _, candidate := range candidates {
		if candidate == nil || candidate.SerialNumber == nil {
			continue
		}
		serial := candidate.SerialNumber.String()
		if seen[serial] {
			continue
		}
		seen[serial] = true
		into = append(into, candidate)
		if stopWhen != nil && stopWhen(candidate) {
			return into, true
		}
	}
	return into, false
}

func normalizeIssuerSourceInfo(src source.Info) source.Info {
	info := src
	switch src.Format {
	case source.FormatPKCS7:
		info.Type = source.Extracted
		info.Description = "extracted from PKCS#7"
	case source.FormatPEM:
		info.Description = "downloaded PEM"
	}
	return info
}

// markSerialSeen records cert in seen and reports whether the serial was already present.
func markSerialSeen(seen map[string]bool, cert *x509.Certificate) bool {
	if cert == nil || cert.SerialNumber == nil {
		return false
	}
	serial := cert.SerialNumber.String()
	if seen[serial] {
		return true
	}
	seen[serial] = true
	return false
}

func serialSeenSet(certs []*x509.Certificate) map[string]bool {
	seen := make(map[string]bool)
	for _, c := range certs {
		if c != nil && c.SerialNumber != nil {
			seen[c.SerialNumber.String()] = true
		}
	}
	return seen
}

func warnPKCS7Bundle(w io.Writer, child *x509.Certificate, candidates []*x509.Certificate) {
	_, matched := aia.SelectIssuer(child, candidates)
	if !matched && len(candidates) > 1 {
		warnf(w, "Warning: PKCS#7 bundle contains %d certs, no exact issuer match found, using first cert\n", len(candidates))
	}
}

func warnPEMDownload(w io.Writer, url string, format source.Format) {
	if format == source.FormatPEM {
		warnf(w, "Warning: CA Issuers URL %s returned PEM format (RFC 5280 requires DER/BER)\n", url)
	}
}
