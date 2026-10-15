package ocsp

import (
	"bytes"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xocsp "golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/testpki"
)

func TestParseOCSP_Invalid(t *testing.T) {
	_, err := ParseOCSP([]byte("not an ocsp response"))
	if err == nil {
		t.Fatal("expected error for invalid OCSP data")
	}
}

func TestParseOCSP_InvalidPEM(t *testing.T) {
	pemData := `-----BEGIN OCSP RESPONSE-----
bm90IHZhbGlkIGRhdGE=
-----END OCSP RESPONSE-----`

	_, err := ParseOCSP([]byte(pemData))
	if err == nil {
		t.Fatal("expected error for invalid PEM OCSP data")
	}
}

func TestGetOCSPs_NoValidOCSPs(t *testing.T) {
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.ocsp")
	if err := os.WriteFile(invalidFile, []byte("not valid"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := GetOCSPs(tmpDir, nil)
	if err == nil {
		t.Fatal("expected error when no valid OCSP responses found")
	}
}

func TestGetOCSPs_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a non-OCSP file to ensure directory isn't empty but has no OCSP files
	if err := os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	resps, err := GetOCSPs(tmpDir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resps) != 0 {
		t.Errorf("expected 0 responses for empty directory, got %d", len(resps))
	}
}

func TestGetOCSPs_NotFound(t *testing.T) {
	_, err := GetOCSPs("/nonexistent/path", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestGetOCSPs_SkipsInvalidFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an invalid OCSP file and a non-OCSP file
	if err := os.WriteFile(filepath.Join(tmpDir, "invalid.ocsp"), []byte("not valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "another.ocsp"), []byte("also not valid"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Should return error since all OCSP files are invalid
	_, err := GetOCSPs(tmpDir, nil)
	if err == nil {
		t.Fatal("expected error when all OCSP files are invalid")
	}
}

func TestInfoFromDownloadedResponse(t *testing.T) {
	response := &xocsp.Response{Raw: []byte{1, 2, 3}}
	requestInfo := &RequestInfo{
		Nonce:         []byte{0xaa},
		NonceHex:      "aa",
		NonceLen:      1,
		RequestLen:    42,
		HashAlgorithm: "SHA256",
	}

	info := infoFromDownloadedResponse(response, requestInfo, "http://ocsp.example.test")
	if info == nil {
		t.Fatal("expected info")
	}
	if info.Response != response {
		t.Fatal("expected response to be copied")
	}
	if info.FilePath != "http://ocsp.example.test" {
		t.Fatalf("expected URL as file path, got %q", info.FilePath)
	}
	if info.Source.Type != source.Downloaded || info.Source.URL != "http://ocsp.example.test" {
		t.Fatalf("unexpected source: %+v", info.Source)
	}
	if info.Source.Format != source.FormatDER {
		t.Fatalf("unexpected format: %q", info.Source.Format)
	}
	if info.Hash == "" {
		t.Fatal("expected hash")
	}
	if info.RequestInfo == nil {
		t.Fatal("expected request info")
	}
	if info.RequestInfo.NonceHex != "aa" || info.RequestInfo.NonceLen != 1 || info.RequestInfo.RequestLen != 42 || info.RequestInfo.HashAlgorithm != "SHA256" {
		t.Fatalf("request metadata not copied: %+v", info)
	}
}

func TestGetOCSPs_ReportsSkippedFiles(t *testing.T) {
	dir := t.TempDir()
	valid, err := os.ReadFile(filepath.Join("..", "..", "tests", "ocsps", "good-leaf.ocsp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "valid.ocsp"), valid, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.ocsp"), []byte("not valid"), 0o644); err != nil {
		t.Fatal(err)
	}

	var diagnostics bytes.Buffer
	responses, err := GetOCSPs(dir, &diagnostics)
	if err != nil || len(responses) != 1 {
		t.Fatalf("GetOCSPs() = %d responses, %v; want the valid one", len(responses), err)
	}
	if !strings.Contains(diagnostics.String(), "Warning: skipped "+filepath.Join(dir, "broken.ocsp")) {
		t.Fatalf("diagnostics = %q, want a warning for broken.ocsp", diagnostics.String())
	}
}

func TestResponderCertificate(t *testing.T) {
	issuer := testpki.Issue(t, "Issuer", nil, testpki.CA())
	responder := testpki.Issue(t, "Responder", issuer, testpki.Serial(2), testpki.OCSPSigning())
	withCertificate := testpki.OCSPResponse(t, issuer, responder, xocsp.Response{
		Status:       xocsp.Good,
		SerialNumber: big.NewInt(3),
		ThisUpdate:   testpki.NotBefore,
		Certificate:  responder.Std,
	})
	withoutCertificate := testpki.OCSPResponse(t, issuer, issuer, xocsp.Response{
		Status:       xocsp.Good,
		SerialNumber: big.NewInt(3),
		ThisUpdate:   testpki.NotBefore,
	})

	got, err := (&Info{Response: withCertificate}).ResponderCertificate()
	if err != nil || got == nil || got.Subject.CommonName != "Responder" {
		t.Fatalf("ResponderCertificate() = %v, %v; want the embedded responder", got, err)
	}
	for _, info := range []*Info{nil, {}, {Response: withoutCertificate}} {
		if got, err := info.ResponderCertificate(); got != nil || err != nil {
			t.Fatalf("ResponderCertificate() without an embedded certificate = %v, %v", got, err)
		}
	}
}

func TestResponderCertificateAcceptsCompatibilityCertificates(t *testing.T) {
	der, err := os.ReadFile(filepath.Join("..", "..", "tests", "pkits", "certs", "ValiddistributionPointTest4EE.crt"))
	if err != nil {
		t.Fatal(err)
	}
	info := &Info{Response: &xocsp.Response{Certificate: &x509.Certificate{Raw: der}}}
	got, err := info.ResponderCertificate()
	if err != nil || got == nil || !bytes.Equal(got.Raw, der) {
		t.Fatalf("ResponderCertificate() = %v, %v; want the embedded certificate", got, err)
	}
}
