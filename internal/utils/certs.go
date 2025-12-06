package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

func GetCertificates(path string) ([]*x509.Certificate, error) {
	certFiles, err := GetCertFiles(path)
	if err != nil {
		return nil, err
	}

	certs := []*x509.Certificate{}
	for _, f := range certFiles {
		c, err := GetCertificate(f)
		if err != nil {
			continue
		}
		certs = append(certs, c)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in %s", path)
	}

	return FindLongestChain(certs)
}

func FindLongestChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	subjectMap := make(map[string]*x509.Certificate)

	for _, c := range certs {
		subjectMap[c.Subject.String()] = c
	}

	var longestChain []*x509.Certificate

	for _, leaf := range certs {
		chain := []*x509.Certificate{leaf}
		current := leaf

		for {
			if current.Subject.String() == current.Issuer.String() {
				break
			}

			issuer := subjectMap[current.Issuer.String()]
			if issuer == nil {
				break
			}

			alreadyInChain := slices.Contains(chain, issuer)
			if alreadyInChain {
				break
			}

			chain = append(chain, issuer)
			current = issuer
		}

		if len(chain) > len(longestChain) {
			longestChain = chain
		}
	}

	if len(longestChain) == 0 {
		return nil, fmt.Errorf("could not find any valid certificate chain")
	}

	return longestChain, nil
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
