package cert

import (
	"encoding/pem"
	"fmt"

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
}

func ParseCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		return x509.ParseCertificate(block.Bytes)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PEM or DER certificate: %w", err)
	}
	return cert, nil
}

func GetCertFiles(path string) ([]string, error) {
	return io.GetFilesWithExtensions(path, extensions...)
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

func getCertType(cert *x509.Certificate, position, chainLen int) string {
	if position == 0 {
		return "leaf"
	}
	if position == chainLen-1 && isSelfSigned(cert) {
		return "root"
	}
	return "intermediate"
}
