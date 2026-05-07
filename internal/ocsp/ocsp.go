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
	Source   string // Source description: "local", "downloaded", etc.

	// Request debug info (populated when auto-fetching)
	RequestNonce         []byte // Nonce sent in request
	RequestNonceHex      string // Hex representation of nonce
	RequestNonceLen      int    // Length of nonce in request
	RequestRawLen        int    // Length of raw OCSP request bytes
	RequestHashAlgorithm string // Hash algorithm used for CertID (e.g., "SHA256")
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
