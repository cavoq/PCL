package operator

import (
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

// signedCRLWithCA builds a CRL signed by ca and an impostor cert with the same
// issuer DN/AKI but a different key (DN-only match).
func signedCRLWithCA(t *testing.T) (*x509.RevocationList, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cryptopkix.Name{CommonName: "CRL Signer CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x0c, 0x0a},
	}
	caDER, err := cryptox509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	cryptoCA, err := cryptox509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse crypto CA: %v", err)
	}

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	crlDER, err := cryptox509.CreateRevocationList(rand.Reader, &cryptox509.RevocationList{
		ThisUpdate: now,
		NextUpdate: now.Add(30 * 24 * time.Hour),
		Number:     big.NewInt(1),
	}, cryptoCA, key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	revocationList, err := crl.ParseCRL(crlDER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate impostor key: %v", err)
	}
	impostorDER, err := cryptox509.CreateCertificate(rand.Reader, &cryptox509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      template.Subject,
		NotBefore:    template.NotBefore,
		NotAfter:     template.NotAfter,
		SubjectKeyId: template.SubjectKeyId,
	}, template, &wrongKey.PublicKey, wrongKey)
	if err != nil {
		t.Fatalf("create impostor: %v", err)
	}
	impostor, err := x509.ParseCertificate(impostorDER)
	if err != nil {
		t.Fatalf("parse impostor: %v", err)
	}

	return revocationList, impostor, ca
}

func TestCRLSignedBy_chainOrder_table(t *testing.T) {
	revocationList, impostor, ca := signedCRLWithCA(t)
	crlInfo := &crl.Info{CRL: revocationList}
	op := CRLSignedBy{}

	tests := []struct {
		name    string
		chain   []*x509.Certificate
		wantOK  bool
	}{
		{
			name:   "impostor then real signer: must not stop at DN-only match",
			chain:  []*x509.Certificate{impostor, ca},
			wantOK: true,
		},
		{
			name:   "real signer first: straightforward pass",
			chain:  []*x509.Certificate{ca, impostor},
			wantOK: true,
		},
		{
			name:   "impostor only: no valid signature",
			chain:  []*x509.Certificate{impostor},
			wantOK: false,
		},
		{
			name:   "unrelated CA only: CRL not applicable",
			chain:  []*x509.Certificate{{Subject: pkix.Name{CommonName: "Other"}, SerialNumber: big.NewInt(1), IsCA: true}},
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chainInfos := make([]*cert.Info, len(tt.chain))
			for i, c := range tt.chain {
				chainInfos[i] = &cert.Info{Cert: c}
			}
			ctx := &EvaluationContext{CRLs: []*crl.Info{crlInfo}, Chain: chainInfos}
			got, err := op.Evaluate(nil, ctx, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantOK {
				t.Fatalf("crlSignedBy = %v, want %v", got, tt.wantOK)
			}
		})
	}
}
