package ocsp

import (
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/loader"
)

var extensions = []string{".ocsp", ".der", ".pem"}

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
	return loader.GetFiles(path, extensions...)
}

func GetOCSPs(path string) ([]*Info, error) {
	results, err := loader.LoadAll(
		path,
		extensions,
		GetOCSP,
		func(resp *ocsp.Response) []byte { return resp.Raw },
	)
	if err != nil {
		return nil, err
	}

	infos := make([]*Info, len(results))
	for i, r := range results {
		infos[i] = &Info{
			Response: r.Data,
			FilePath: r.FilePath,
			Hash:     r.Hash,
		}
	}
	return infos, nil
}
