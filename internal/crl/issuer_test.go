package crl

import (
	"math/big"
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
