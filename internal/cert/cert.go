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

func GetCertType(cert *x509.Certificate, _, _ int) string {
	if cert == nil {
		return ""
	}

	if cert.BasicConstraintsValid && cert.IsCA {
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
