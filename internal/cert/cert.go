package cert

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zmap/zcrypto/x509"
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
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot access path %s: %w", path, err)
	}

	var files []string

	if info.IsDir() {
		err := filepath.Walk(path, func(p string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if fi.IsDir() {
				return nil
			}
			ext := filepath.Ext(p)
			if ext == ".pem" || ext == ".der" || ext == ".crt" || ext == ".cer" {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		files = append(files, path)
	}

	return files, nil
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
