// Package cert provides certificate loading, parsing and chain building.
package cert

import (
	"encoding/pem"
	"fmt"

	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/io"
)

var extensions = []string{".pem", ".der", ".crt", ".cer"}

type Info struct {
	Cert     *x509.Certificate
	FilePath string
	Hash     string
	Position int
	Type     string
	Source   source.Info
	Format   source.Format
}

func ParseCertificate(data []byte) (*x509.Certificate, error) {
	cert, _, err := parseCertificate(data)
	return cert, err
}

func parseCertificate(data []byte) (*x509.Certificate, source.Format, error) {
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", err
		}
		return cert, source.FormatPEM, nil
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse PEM or DER certificate: %w", err)
	}
	return cert, source.FormatDER, nil
}

func GetCertFiles(path string) ([]string, error) {
	return io.GetFilesWithExtensions(path, extensions...)
}

func IsSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// IsCA reports whether the certificate's strictly decoded basicConstraints
// extension asserts cA. Certificate roles and policy certType filters share
// this decision so a malformed extension classifies the same everywhere.
func IsCA(cert *x509.Certificate) bool {
	basicConstraints, valid := basicConstraintsProfileFacts(cert)
	return valid && basicConstraints.CA
}

// GetCertType classifies a certificate's role from its own contents.
func GetCertType(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	if IsCA(cert) {
		if IsSelfSigned(cert) {
			return "root"
		}
		return "intermediate"
	}

	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOcspSigning {
			return "ocspSigning"
		}
	}

	return "leaf"
}
