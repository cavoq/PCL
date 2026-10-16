// Package ocsp provides OCSP request building and response parsing.
package ocsp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"

	zx509 "github.com/zmap/zcrypto/x509"
	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/certparse"
	"github.com/cavoq/PCL/internal/source"
)

var extensions = []string{".ocsp", ".der", ".pem"}

type Info struct {
	Response *ocsp.Response
	FilePath string
	Hash     string
	Source   source.Info

	// Request debug info (populated when auto-fetching)
	RequestInfo *RequestInfo
}

// ResponderCertificate returns the responder certificate embedded in the
// response, parsed like every other certificate, or nil when there is none.
func (info *Info) ResponderCertificate() (*zx509.Certificate, error) {
	if info == nil || info.Response == nil || info.Response.Certificate == nil {
		return nil, nil
	}
	return certparse.ParseCertificate(info.Response.Certificate.Raw)
}

// standardCertificate parses a zcrypto certificate with crypto/x509, which
// golang.org/x/crypto/ocsp works with.
func standardCertificate(certificate *zx509.Certificate) (*x509.Certificate, error) {
	if certificate == nil {
		return nil, nil
	}
	return x509.ParseCertificate(certificate.Raw)
}

// ParseOCSP parses a single DER or PEM OCSP response.
func ParseOCSP(data []byte) (*ocsp.Response, error) {
	responses, _, err := parseOCSPs(data)
	if err != nil {
		return nil, err
	}
	if len(responses) != 1 {
		return nil, fmt.Errorf("expected one OCSP response, found %d", len(responses))
	}
	return responses[0], nil
}

// parseOCSPs parses a DER OCSP response or every OCSP RESPONSE block of PEM
// data.
func parseOCSPs(data []byte) ([]*ocsp.Response, source.Format, error) {
	return source.DecodePEMOrDER(data, "OCSP RESPONSE", ParseResponse)
}

// GetOCSPs loads the OCSP responses of a file, or of every OCSP response file
// in a directory. Directory files that cannot be read or parsed are reported
// to w and skipped; the load fails when no file yields a response.
func GetOCSPs(path string, w io.Writer) ([]*Info, error) {
	loaded, err := source.LoadFiles(path, extensions, parseOCSPs, w)
	if err != nil {
		return nil, err
	}
	infos := make([]*Info, 0, len(loaded))
	for _, response := range loaded {
		hash := sha256.Sum256(response.Item.Raw)
		infos = append(infos, &Info{
			Response: response.Item,
			FilePath: response.Path,
			Hash:     hex.EncodeToString(hash[:]),
			Source:   source.Info{Type: source.Local, Format: response.Format},
		})
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
	}

	if len(resp.Raw) > 0 {
		hash := sha256.Sum256(resp.Raw)
		info.Hash = hex.EncodeToString(hash[:])
	}

	info.RequestInfo = requestInfo

	return info
}
