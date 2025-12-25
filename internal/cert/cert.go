package cert

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/io"
)

type Info struct {
	Cert     *x509.Certificate
	FilePath string
	Hash     string
	Position int
	Type     string
}

func GetCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

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
	return io.GetFilesWithExtensions(path, ".pem", ".der", ".crt", ".cer")
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
