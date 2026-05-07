package linter

import (
	"fmt"

	"github.com/cavoq/PCL/internal/cert"
)

// loadCertificates loads leaf certificates from paths and URLs specified in config.
func loadCertificates(cfg Config) ([]*cert.Info, func(), error) {
	var cleanup func()
	var certs []*cert.Info

	if cfg.CertPath != "" {
		loaded, err := cert.LoadCertificates(cfg.CertPath)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to load certificates: %w", err)
		}
		certs = append(certs, loaded...)
	}

	if len(cfg.CertURLs) > 0 {
		loaded, tempCleanup, err := cert.DownloadAndLoadCertificates(cfg.CertURLs, cfg.CertTimeout, cfg.CertSaveDir)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to download certificates: %w", err)
		}
		if tempCleanup != nil {
			cleanup = tempCleanup
		}
		certs = append(certs, loaded...)
	}

	if len(certs) == 0 {
		return nil, cleanup, fmt.Errorf("no leaf certificates provided")
	}

	return certs, cleanup, nil
}

// loadIssuers loads issuer certificates from paths and URLs specified in config.
func loadIssuers(cfg Config, existingCleanup func()) ([]*cert.Info, func(), error) {
	cleanup := existingCleanup
	var issuers []*cert.Info

	for _, path := range cfg.IssuerPaths {
		loaded, err := cert.LoadCertificates(path)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to load issuer certificates from %s: %w", path, err)
		}
		issuers = append(issuers, loaded...)
	}

	if len(cfg.IssuerURLs) > 0 {
		loaded, tempCleanup, err := cert.DownloadAndLoadCertificates(cfg.IssuerURLs, cfg.CertTimeout, cfg.CertSaveDir)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to download issuer certificates: %w", err)
		}
		if tempCleanup != nil {
			cleanup = tempCleanup
		}
		issuers = append(issuers, loaded...)
	}

	if len(issuers) == 0 {
		return nil, cleanup, fmt.Errorf("no issuer certificates provided")
	}

	return issuers, cleanup, nil
}
