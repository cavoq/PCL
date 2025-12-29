package ocsp

import (
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/io"
	"github.com/cavoq/PCL/internal/loader"
)

var extensions = []string{".ocsp", ".der", ".pem"}

type Info struct {
	Response *ocsp.Response
	FilePath string
	Hash     string
}

func ParseOCSP(data []byte) (*ocsp.Response, error) {
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
	return io.GetFilesWithExtensions(path, extensions...)
}

func GetOCSPs(path string) ([]*Info, error) {
	results, err := loader.LoadAll(
		path,
		extensions,
		ParseOCSP,
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
