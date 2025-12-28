package ocsp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/io"
)

type Info struct {
	Response *ocsp.Response
	FilePath string
	Hash     string
}

func GetOCSP(path string) (*ocsp.Response, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block != nil && block.Type == "OCSP RESPONSE" {
		return ocsp.ParseResponse(block.Bytes, nil)
	}

	resp, err := ocsp.ParseResponse(data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PEM or DER OCSP response: %w", err)
	}
	return resp, nil
}

func GetOCSPFiles(path string) ([]string, error) {
	return io.GetFilesWithExtensions(path, ".ocsp", ".der", ".pem")
}

func GetOCSPs(path string) ([]*Info, error) {
	files, err := GetOCSPFiles(path)
	if err != nil {
		return nil, err
	}

	resps := make([]*Info, 0, len(files))
	for _, f := range files {
		resp, err := GetOCSP(f)
		if err != nil {
			continue
		}

		hash := sha256.Sum256(resp.Raw)
		resps = append(resps, &Info{
			Response: resp,
			FilePath: f,
			Hash:     hex.EncodeToString(hash[:]),
		})
	}

	if len(resps) == 0 && len(files) > 0 {
		return nil, fmt.Errorf("no valid OCSP responses found in %s", path)
	}

	return resps, nil
}
