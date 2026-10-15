// Package ocsp provides OCSP request building and response parsing.
package ocsp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/fsutil"
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
	return fsutil.GetFilesWithExtensions(path, extensions...)
}

// GetOCSPs loads the OCSP response of a file, or of every OCSP response file
// in a directory. Directory files that cannot be read or parsed are reported
// to w and skipped; the load fails when no file yields a response.
func GetOCSPs(path string, w io.Writer) ([]*Info, error) {
	files, err := GetOCSPFiles(path)
	if err != nil {
		return nil, err
	}

	infos := make([]*Info, 0, len(files))
	var skipped []error
	for _, file := range files {
		resp, format, err := loadOCSPFile(file)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("%s: %w", file, err))
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

	if len(infos) == 0 && len(skipped) > 0 {
		return nil, fmt.Errorf("no valid items found in %s: %w", path, skipped[0])
	}
	fsutil.ReportSkipped(w, skipped)
	return infos, nil
}

func loadOCSPFile(file string) (*ocsp.Response, source.Format, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, "", err
	}
	return parseOCSP(data)
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
