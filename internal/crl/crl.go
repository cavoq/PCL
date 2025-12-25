package crl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/io"
)

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
	return io.GetFilesWithExtensions(path, ".crl", ".pem")
}

func GetCRLs(path string) ([]*Info, error) {
	files, err := GetCRLFiles(path)
	if err != nil {
		return nil, err
	}

	crls := make([]*Info, 0, len(files))
	for _, f := range files {
		crl, err := GetCRL(f)
		if err != nil {
			continue
		}

		hash := sha256.Sum256(crl.Raw)
		crls = append(crls, &Info{
			CRL:      crl,
			FilePath: f,
			Hash:     hex.EncodeToString(hash[:]),
		})
	}

	if len(crls) == 0 && len(files) > 0 {
		return nil, fmt.Errorf("no valid CRLs found in %s", path)
	}

	return crls, nil
}
