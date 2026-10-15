package linter

import (
	"fmt"
	"io"

	"github.com/cavoq/PCL/internal/cert"
)

// loadCertificates loads leaf certificates from paths and URLs specified in config.
func loadCertificates(cfg Config, w io.Writer) ([]*cert.Info, func(), error) {
	var cleanup func()
	var certs []*cert.Info

	if cfg.CertPath != "" {
		loaded, err := cert.LoadCertificates(cfg.CertPath, w)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to load certificates: %w", err)
		}
		certs = append(certs, loaded...)
	}

	if len(cfg.CertURLs) > 0 {
		loaded, tempCleanup, err := cert.DownloadAndLoadCertificates(cfg.CertURLs, cfg.CertTimeout, cfg.CertSaveDir)
		cleanup = composeCleanup(cleanup, tempCleanup)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to download certificates: %w", err)
		}
		certs = append(certs, loaded...)
	}

	if len(certs) == 0 {
		return nil, cleanup, fmt.Errorf("no leaf certificates provided")
	}

	return certs, cleanup, nil
}

// loadIssuers loads issuer certificates from paths and URLs specified in config.
func loadIssuers(cfg Config, w io.Writer) ([]*cert.Info, func(), error) {
	var cleanup func()
	var issuers []*cert.Info

	for _, path := range cfg.IssuerPaths {
		loaded, err := cert.LoadCertificates(path, w)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to load issuer certificates from %s: %w", path, err)
		}
		issuers = append(issuers, loaded...)
	}

	if len(cfg.IssuerURLs) > 0 {
		loaded, tempCleanup, err := cert.DownloadAndLoadCertificates(cfg.IssuerURLs, cfg.CertTimeout, cfg.CertSaveDir)
		cleanup = composeCleanup(cleanup, tempCleanup)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to download issuer certificates: %w", err)
		}
		issuers = append(issuers, loaded...)
	}

	if len(issuers) == 0 {
		return nil, cleanup, fmt.Errorf("no issuer certificates provided")
	}

	return issuers, cleanup, nil
}

// loadTrustAnchors loads only local, explicitly trusted certificates. Trust
// is a caller decision, so anchors are never downloaded or inferred from the
// issuer pool.
func loadTrustAnchors(paths []string, w io.Writer) ([]*cert.Info, error) {
	var anchors []*cert.Info
	for _, path := range paths {
		loaded, err := cert.LoadCertificates(path, w)
		if err != nil {
			return nil, fmt.Errorf("failed to load trust anchors from %s: %w", path, err)
		}
		anchors = append(anchors, loaded...)
	}
	if len(paths) > 0 && len(anchors) == 0 {
		return nil, fmt.Errorf("no trust-anchor certificates provided")
	}
	return anchors, nil
}

func composeCleanup(first, second func()) func() {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	return func() {
		second()
		first()
	}
}
