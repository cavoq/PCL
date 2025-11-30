package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

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

	files := []string{}

	if info.IsDir() {
		err := filepath.Walk(path, func(p string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if fi.IsDir() {
				return nil
			}
			ext := filepath.Ext(p)
			if ext == ".pem" || ext == ".der" {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		ext := filepath.Ext(path)
		if ext == ".pem" || ext == ".der" {
			files = append(files, path)
		}
	}

	return files, nil
}

func GetCertificates(path string) ([]*x509.Certificate, error) {
	certFiles, err := GetCertFiles(path)

	if err != nil {
		return nil, err
	}

	certs := []*x509.Certificate{}

	for _, f := range certFiles {
		c, err := GetCertificate(f)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate %s: %w", f, err)
		}
		certs = append(certs, c)
	}

	return certs, nil
}
