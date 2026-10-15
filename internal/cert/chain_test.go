package cert

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/testpki"
)

func TestLoadCertificates_Chain(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chain) != 3 {
		t.Fatalf("expected 3 certs in chain, got %d", len(chain))
	}

	if chain[0].Type != "leaf" {
		t.Errorf("expected first cert to be leaf, got %s", chain[0].Type)
	}

	if chain[1].Type != "intermediate" {
		t.Errorf("expected second cert to be intermediate, got %s", chain[1].Type)
	}

	if chain[2].Type != "root" {
		t.Errorf("expected third cert to be root, got %s", chain[2].Type)
	}
}

func TestLoadCertificates_SingleCert(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs/leaf.pem", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chain) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(chain))
	}

	if chain[0].Type != "leaf" {
		t.Errorf("expected cert type leaf, got %s", chain[0].Type)
	}
}

func TestParseCertificates(t *testing.T) {
	data, err := os.ReadFile("../../tests/certs/leaf.pem")
	if err != nil {
		t.Fatal(err)
	}
	certs, format, err := ParseCertificates(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 || format != source.FormatPEM {
		t.Fatalf("parsed %d certificates as %s, want 1 as PEM", len(certs), format)
	}

	if cert := certs[0]; cert.Subject.CommonName != "leaf.example.test" {
		t.Errorf("expected CN 'leaf.example.test', got %s", cert.Subject.CommonName)
	}
}

func TestParseCertificates_inputs(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA())
	leaf := testpki.Issue(t, "Leaf", root, testpki.Serial(2))
	rootPEM := testpki.PEM("CERTIFICATE", root.DER)
	leafPEM := testpki.PEM("CERTIFICATE", leaf.DER)
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	tests := []struct {
		name    string
		data    []byte
		want    []string
		format  source.Format
		wantErr string
	}{
		{name: "DER", data: leaf.DER, want: []string{"Leaf"}, format: source.FormatDER},
		{name: "PEM bundle", data: join(leafPEM, rootPEM), want: []string{"Leaf", "Root"}, format: source.FormatPEM},
		{
			name:   "other PEM blocks are skipped",
			data:   join(testpki.PEM("PRIVATE KEY", []byte{1}), leafPEM),
			want:   []string{"Leaf"},
			format: source.FormatPEM,
		},
		{
			name:    "malformed certificate in a bundle",
			data:    join(leafPEM, testpki.PEM("CERTIFICATE", []byte{0x30, 0x00})),
			wantErr: "PEM CERTIFICATE block 2",
		},
		{name: "PEM without certificates", data: testpki.PEM("X509 CRL", []byte{1}), wantErr: "no CERTIFICATE block"},
		{name: "neither PEM nor DER", data: []byte("garbage"), wantErr: "PEM or DER"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, format, err := ParseCertificates(tt.data)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, cert := range certs {
				got = append(got, cert.Subject.CommonName)
			}
			if !slices.Equal(got, tt.want) || format != tt.format {
				t.Fatalf("parsed %v as %s, want %v as %s", got, format, tt.want, tt.format)
			}
		})
	}
}

// A PEM bundle passed as --issuer supplies every certificate it contains.
func TestLoadCertificates_PEMBundleBuildsChain(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs/chain.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatal(err)
	}
	var roles []string
	for _, info := range chain {
		roles = append(roles, info.Type)
	}
	if want := []string{TypeLeaf, TypeIntermediate, TypeRoot}; !slices.Equal(roles, want) {
		t.Fatalf("chain from chain.pem = %v, want %v", roles, want)
	}
}

func TestBuildChain_Positions(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, c := range chain {
		if position, ok := ChainIndex(c, chain); !ok || position != i {
			t.Errorf("cert %d: ChainIndex = %d, %v", i, position, ok)
		}
	}
}

func TestBuildChain_Hashes(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, c := range chain {
		if c.Hash == "" {
			t.Errorf("cert %d: hash should not be empty", i)
		}
		if len(c.Hash) != 64 {
			t.Errorf("cert %d: expected 64 char hash, got %d", i, len(c.Hash))
		}
	}
}

func TestBuildChain_FilePaths(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, c := range chain {
		if c.FilePath == "" {
			t.Errorf("cert %d: file path should not be empty", i)
		}
		ext := filepath.Ext(c.FilePath)
		if ext != ".pem" {
			t.Errorf("cert %d: expected .pem extension, got %s", i, ext)
		}
	}
}

func TestGetCertType_ClassifiesIndependentOfPosition(t *testing.T) {
	root := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Root"},
		Issuer:                pkix.Name{CommonName: "Root"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if got := GetCertType(root); got != "root" {
		t.Fatalf("expected root independent of position, got %q", got)
	}

	intermediate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Intermediate"},
		Issuer:                pkix.Name{CommonName: "Root"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if got := GetCertType(intermediate); got != "intermediate" {
		t.Fatalf("expected intermediate independent of position, got %q", got)
	}

	ocspSigner := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "OCSP Signer"},
		Issuer:      pkix.Name{CommonName: "Intermediate"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOcspSigning},
	}
	if got := GetCertType(ocspSigner); got != "ocspSigning" {
		t.Fatalf("expected ocspSigning independent of position, got %q", got)
	}

	leaf := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Leaf"},
		Issuer:  pkix.Name{CommonName: "Intermediate"},
	}
	if got := GetCertType(leaf); got != "leaf" {
		t.Fatalf("expected leaf independent of position, got %q", got)
	}
}

func TestLoadCertificates_ReportsSkippedFiles(t *testing.T) {
	dir := t.TempDir()
	valid, err := os.ReadFile("../../tests/certs/leaf.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "leaf.pem"), valid, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.pem"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}

	var diagnostics bytes.Buffer
	certs, err := LoadCertificates(dir, &diagnostics)
	if err != nil || len(certs) != 1 {
		t.Fatalf("LoadCertificates() = %d certificates, %v; want the valid one", len(certs), err)
	}
	if !strings.Contains(diagnostics.String(), "Warning: skipped "+filepath.Join(dir, "broken.pem")) {
		t.Fatalf("diagnostics = %q, want a warning for broken.pem", diagnostics.String())
	}
}
