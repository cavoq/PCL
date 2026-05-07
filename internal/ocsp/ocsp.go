package ocsp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/io"
	"github.com/cavoq/PCL/internal/source"
)

var extensions = []string{".ocsp", ".der", ".pem"}

type Info struct {
	Response *ocsp.Response
	FilePath string
	Hash     string
	Source   source.Info
	Format   source.Format

	// Request debug info (populated when auto-fetching)
	RequestInfo *RequestInfo
}

func ParseOCSP(data []byte) (*ocsp.Response, error) {
	resp, _, err := parseOCSP(data)
	return resp, err
}

func parseOCSP(data []byte) (*ocsp.Response, source.Format, error) {
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "OCSP RESPONSE" {
		resp, err := ocsp.ParseResponse(block.Bytes, nil)
		if err != nil {
			return nil, "", err
		}
		return resp, source.FormatPEM, nil
	}

	resp, err := ocsp.ParseResponse(data, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse PEM or DER OCSP response: %w", err)
	}
	return resp, source.FormatDER, nil
}

func GetOCSPFiles(path string) ([]string, error) {
	return io.GetFilesWithExtensions(path, extensions...)
}

func GetOCSPs(path string) ([]*Info, error) {
	files, err := GetOCSPFiles(path)
	if err != nil {
		return nil, err
	}

	infos := make([]*Info, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		resp, format, err := parseOCSP(data)
		if err != nil {
			continue
		}

		hash := sha256.Sum256(resp.Raw)
		infos = append(infos, &Info{
			Response: resp,
			FilePath: file,
			Hash:     hex.EncodeToString(hash[:]),
			Source:   source.Info{Type: source.Local, Format: format},
			Format:   format,
		})
	}

	if len(infos) == 0 && len(files) > 0 {
		return nil, fmt.Errorf("no valid items found in %s", path)
	}
	return infos, nil
}

func infoFromDownloadedResponse(resp *ocsp.Response, requestInfo *RequestInfo, url string) *Info {
	if resp == nil {
		return nil
	}

	info := &Info{
		Response: resp,
		FilePath: url,
		Source:   source.Info{Type: source.Downloaded, URL: url, Format: source.FormatDER},
		Format:   source.FormatDER,
	}

	if len(resp.Raw) > 0 {
		hash := sha256.Sum256(resp.Raw)
		info.Hash = hex.EncodeToString(hash[:])
	}

	info.RequestInfo = requestInfo

	return info
}
