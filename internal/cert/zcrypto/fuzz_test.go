package zcrypto

import (
	"testing"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/testpki"
)

func certificateSeeds(t testing.TB) [][]byte {
	return testpki.SeedFiles(t, "tests/pkits/certs/*.crt", "tests/certs/*.pem", "internal/cert/testdata/*.pem")
}

// FuzzBuildTree projects every certificate zcrypto accepts. The strict
// extension and TBS decoders run on its raw encodings.
func FuzzBuildTree(f *testing.F) {
	for _, seed := range certificateSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return
		}
		if BuildTree(cert) == nil {
			t.Fatal("BuildTree returned no tree")
		}
	})
}

// FuzzCertificateExtensionParsers runs each strict extension parser on
// arbitrary values, which zcrypto would otherwise reject before projection.
func FuzzCertificateExtensionParsers(f *testing.F) {
	for _, seed := range certificateSeeds(f) {
		cert, err := x509.ParseCertificate(seed)
		if err != nil {
			continue
		}
		for _, extension := range cert.Extensions {
			if _, ok := certificateExtensionParsers[extension.Id.String()]; ok {
				f.Add(extension.Id.String(), extension.Value)
			}
		}
	}
	f.Fuzz(func(t *testing.T, identifier string, value []byte) {
		parser, ok := certificateExtensionParsers[identifier]
		if !ok {
			return
		}
		if projected, err := parser(value); err == nil && projected == nil {
			t.Fatalf("parser for %s returned neither a projection nor an error", identifier)
		}
	})
}

func FuzzTBSCertificateMetadata(f *testing.F) {
	for _, seed := range certificateSeeds(f) {
		if cert, err := x509.ParseCertificate(seed); err == nil {
			f.Add(cert.RawTBSCertificate)
		}
	}
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = parseTBSCertificateMetadata(raw)
	})
}
