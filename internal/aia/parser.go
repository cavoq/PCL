package aia

import (
	"encoding/pem"
	"fmt"

	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
)

func ParseIssuerResponse(data []byte) ([]*x509.Certificate, source.Format, error) {
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return []*x509.Certificate{cert}, source.FormatDER, nil
	}

	pkcs7Certs, err := parsePKCS7CertsOnly(data)
	if err == nil && len(pkcs7Certs) > 0 {
		return pkcs7Certs, source.FormatPKCS7, nil
	}

	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PEM certificate from CA Issuers: %w", err)
		}
		return []*x509.Certificate{cert}, source.FormatPEM, nil
	}

	return nil, "", fmt.Errorf("failed to parse CA Issuers: expected DER certificate, PKCS#7 bundle, or PEM format")
}
