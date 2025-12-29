package crl

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/loader"
)

var extensions = []string{".crl", ".pem"}

type Info struct {
	CRL      *x509.RevocationList
	FilePath string
	Hash     string
}

func GetCRL(path string) (*x509.RevocationList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block != nil && block.Type == "X509 CRL" {
		return x509.ParseRevocationList(block.Bytes)
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PEM or DER CRL: %w", err)
	}
	return crl, nil
}

func GetCRLFiles(path string) ([]string, error) {
	return loader.GetFiles(path, extensions...)
}

func GetCRLs(path string) ([]*Info, error) {
	results, err := loader.LoadAll(
		path,
		extensions,
		GetCRL,
		func(crl *x509.RevocationList) []byte { return crl.Raw },
	)
	if err != nil {
		return nil, err
	}

	infos := make([]*Info, len(results))
	for i, r := range results {
		infos[i] = &Info{
			CRL:      r.Data,
			FilePath: r.FilePath,
			Hash:     r.Hash,
		}
	}
	return infos, nil
}
