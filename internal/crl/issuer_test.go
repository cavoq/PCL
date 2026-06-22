package crl

import (
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestCertMatchesCRLIssuer(t *testing.T) {
	signer := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Signer"},
		SubjectKeyId: []byte{0x01, 0x02, 0x03},
		IsCA:         true,
		SerialNumber: big.NewInt(1),
	}
	other := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Other"},
		SubjectKeyId: []byte{0x04, 0x05, 0x06},
		SerialNumber: big.NewInt(2),
	}

	tests := []struct {
		name string
		cert *x509.Certificate
		crl  *x509.RevocationList
		want bool
	}{
		{
			name: "nil cert",
			crl:  &x509.RevocationList{Issuer: pkix.Name{CommonName: "Signer"}},
		},
		{
			name: "nil crl",
			cert: signer,
		},
		{
			name: "subject match",
			cert: signer,
			crl: &x509.RevocationList{
				Issuer:         pkix.Name{CommonName: "Signer"},
				AuthorityKeyId: []byte{0x99},
			},
			want: true,
		},
		{
			name: "authority key identifier match",
			cert: other,
			crl: &x509.RevocationList{
				Issuer:         pkix.Name{CommonName: "Different Issuer DN"},
				AuthorityKeyId: []byte{0x04, 0x05, 0x06},
			},
			want: true,
		},
		{
			name: "no match",
			cert: signer,
			crl: &x509.RevocationList{
				Issuer:         pkix.Name{CommonName: "Unknown"},
				AuthorityKeyId: []byte{0x07},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CertMatchesCRLIssuer(tt.cert, tt.crl)
			if got != tt.want {
				t.Fatalf("CertMatchesCRLIssuer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigningCertFromPool(t *testing.T) {
	signer := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Signer"},
		SubjectKeyId: []byte{0x07},
		SerialNumber: big.NewInt(3),
	}
	other := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Other"},
		SerialNumber: big.NewInt(4),
	}
	revocationList := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "Signer"},
		AuthorityKeyId: []byte{0x07},
	}

	got := SigningCertFromPool(revocationList, []*x509.Certificate{other, signer})
	if got != signer {
		t.Fatalf("SigningCertFromPool() = %v, want signer", got)
	}
}

func TestResolveIssuerCerts_nilCRL(t *testing.T) {
	signer := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "CA"},
		SerialNumber: big.NewInt(1),
	}
	pool := ResolveIssuerCerts([]*cert.Info{{Cert: signer}}, nil, time.Second, 1, nil)
	if len(pool) != 1 || pool[0] != signer {
		t.Fatalf("ResolveIssuerCerts(nil CRL) = %v", pool)
	}
}

func TestCertSignsCRL_matchesViaSignature(t *testing.T) {
	revocationList, err := ParseCRL(mustReadCRLFixture(t))
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	signer := &x509.Certificate{
		Subject:      revocationList.Issuer,
		SubjectKeyId: revocationList.AuthorityKeyId,
		IsCA:         true,
		SerialNumber: big.NewInt(1),
	}
	if !CertSignsCRL(signer, revocationList) {
		t.Fatal("expected CertSignsCRL true for issuer DN match")
	}
}

func TestSigningCertFromPool_nilWhenNoMatch(t *testing.T) {
	if got := SigningCertFromPool(&x509.RevocationList{
		Issuer: pkix.Name{CommonName: "Nobody"},
	}, []*x509.Certificate{{Subject: pkix.Name{CommonName: "Other"}}}); got != nil {
		t.Fatalf("SigningCertFromPool() = %v, want nil", got)
	}
}

func TestResolveIssuerCerts_skipsFetchWhenSignerInChain(t *testing.T) {
	signer := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Test CA"},
		SubjectKeyId: []byte{0x0a},
		IsCA:         true,
		SerialNumber: big.NewInt(5),
	}
	revocationList := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "Test CA"},
		AuthorityKeyId: []byte{0x0a},
	}
	chain := []*cert.Info{{Cert: signer}}

	pool := ResolveIssuerCerts(chain, revocationList, 0, 0, nil)
	if len(pool) != 1 || pool[0] != signer {
		t.Fatalf("ResolveIssuerCerts() = %v, want chain signer only", pool)
	}
}

func TestInferCACRLFromValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	tests := []struct {
		name string
		crl  *x509.RevocationList
		want bool
	}{
		{
			name: "nil",
		},
		{
			name: "seven days subscriber window",
			crl: &x509.RevocationList{
				ThisUpdate: now,
				NextUpdate: now.Add(7 * 24 * time.Hour),
			},
		},
		{
			name: "eleven days implies other CRL profile",
			crl: &x509.RevocationList{
				ThisUpdate: now,
				NextUpdate: now.Add(11 * 24 * time.Hour),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferCACRLFromValidity(tt.crl)
			if got != tt.want {
				t.Fatalf("inferCACRLFromValidity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsCACRL_usesValidityWhenSignerUnknown(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	crl := &x509.RevocationList{
		Issuer:     pkix.Name{CommonName: "Unknown Root"},
		ThisUpdate: now,
		NextUpdate: now.Add(100 * 24 * time.Hour),
	}

	if !isCACRL(crl, nil) {
		t.Fatal("expected isCACRL true for long validity window without signer in pool")
	}
}

func TestIsCACRL_usesValidityWhenSignerNotCA(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	nonCA := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Wrong Match"},
		SubjectKeyId: []byte{0x01},
		IsCA:         false,
		SerialNumber: big.NewInt(9),
	}
	crl := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "Wrong Match"},
		AuthorityKeyId: []byte{0x01},
		ThisUpdate:     now,
		NextUpdate:     now.Add(100 * 24 * time.Hour),
	}

	if !isCACRL(crl, []*x509.Certificate{nonCA}) {
		t.Fatal("expected isCACRL true via validity when matched signer is not a CA")
	}
}

func TestResolveIssuerCerts_fetchesViaAIA(t *testing.T) {
	parentDER, parent := testCRLIssuerCA(t, "CRL CA")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(parentDER)
	}))
	defer server.Close()

	leaf := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "subscriber"},
		Issuer:                parent.Subject,
		SerialNumber:          big.NewInt(2),
		IssuingCertificateURL: []string{server.URL},
	}
	revocationList := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "Different Issuer DN"},
		AuthorityKeyId: []byte{0x01, 0x02},
	}

	pool := ResolveIssuerCerts([]*cert.Info{{Cert: leaf}}, revocationList, time.Second, 2, nil)
	if len(pool) != 2 {
		t.Fatalf("pool len = %d, want leaf + fetched parent", len(pool))
	}
	signer := SigningCertFromPool(revocationList, pool)
	if signer == nil || signer.Subject.CommonName != "CRL CA" {
		t.Fatalf("SigningCertFromPool() = %v, want CRL CA signer", signer)
	}
}

func TestBuildTreeWithChain_nilCRL(t *testing.T) {
	if got := BuildTreeWithChain(nil, nil); got != nil {
		t.Fatalf("BuildTreeWithChain(nil) = %v, want nil", got)
	}
}

func TestBuildTreeWithChain_isCACRLFromCASigner(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "CA Signer"},
		SubjectKeyId: []byte{0x0b},
		IsCA:         true,
		SerialNumber: big.NewInt(1),
	}
	revocationList := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "CA Signer"},
		AuthorityKeyId: []byte{0x0b},
		ThisUpdate:     now,
		NextUpdate:     now.Add(7 * 24 * time.Hour),
	}

	tree := BuildTreeWithChain(revocationList, []*x509.Certificate{signer})
	if tree == nil {
		t.Fatal("expected CRL tree")
	}
	isCA, ok := tree.Children["isCACRL"]
	if !ok {
		t.Fatal("isCACRL node missing")
	}
	if isCA.Value != true {
		t.Fatalf("isCACRL = %v, want true", isCA.Value)
	}
}

func TestBuildTreeWithChain_isCACRLFalseForShortValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	revocationList := &x509.RevocationList{
		Issuer:     pkix.Name{CommonName: "Unknown"},
		ThisUpdate: now,
		NextUpdate: now.Add(5 * 24 * time.Hour),
	}

	tree := BuildTreeWithChain(revocationList, nil)
	isCA := tree.Children["isCACRL"]
	if isCA.Value != false {
		t.Fatalf("isCACRL = %v, want false", isCA.Value)
	}
}

func TestBuildTree_setsNodes(t *testing.T) {
	revocationList, err := ParseCRL(mustReadCRLFixture(t))
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	tree := BuildTree(revocationList)
	if tree == nil || tree.Children["issuer"] == nil {
		t.Fatal("expected CRL tree with issuer node")
	}
}

func TestBuildTreeWithChain_zeroNextUpdate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	revocationList := &x509.RevocationList{
		Issuer:     pkix.Name{CommonName: "Unknown"},
		ThisUpdate: now,
	}
	tree := BuildTreeWithChain(revocationList, nil)
	if tree.Children["isCACRL"].Value != false {
		t.Fatalf("isCACRL = %v, want false when nextUpdate is zero", tree.Children["isCACRL"].Value)
	}
}

func TestInferCACRLFromValidity_zeroNextUpdate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	if inferCACRLFromValidity(&x509.RevocationList{ThisUpdate: now}) {
		t.Fatal("expected false when nextUpdate is zero")
	}
}

func mustReadCRLFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "test.crl"))
	if err != nil {
		t.Fatalf("read test CRL: %v", err)
	}
	return data
}

func testCRLIssuerCA(t *testing.T, cn string) ([]byte, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cryptopkix.Name{CommonName: cn},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01, 0x02},
	}
	der, err := cryptox509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return der, parsed
}
