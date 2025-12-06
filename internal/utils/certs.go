package utils

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
)

type CertInfo struct {
	Cert     *x509.Certificate
	FilePath string
	Hash     string
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

func GetCertificates(path string) ([]*CertInfo, error) {
	certFiles, err := GetCertFiles(path)
	if err != nil {
		return nil, err
	}

	certs := []*CertInfo{}
	for _, f := range certFiles {
		c, err := GetCertificate(f)
		if err != nil {
			log.Printf("warning: skipping %s: %v", f, err)
			continue
		}
		hash := sha256.Sum256(c.Raw)
		certs = append(certs, &CertInfo{
			Cert:     c,
			FilePath: f,
			Hash:     fmt.Sprintf("%x", hash),
		})
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in %s", path)
	}

	return FindLongestChain(certs)
}

func FindLongestChain(certs []*CertInfo) ([]*CertInfo, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	subjectMap := make(map[string]*CertInfo)

	for _, c := range certs {
		subjectMap[c.Cert.Subject.String()] = c
	}

	var longestChain []*CertInfo

	for _, leaf := range certs {
		chain := []*CertInfo{leaf}
		current := leaf

		for {
			if current.Cert.Subject.String() == current.Cert.Issuer.String() {
				break
			}

			issuer := subjectMap[current.Cert.Issuer.String()]
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
