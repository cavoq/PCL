package operator

import (
	cryptox509 "crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/testpki"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

// signedCRLWithCA builds a CRL signed by ca and an impostor cert with the same
// issuer DN/AKI but a different key (DN-only match).
func signedCRLWithCA(t *testing.T) (*x509.RevocationList, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	ski := testpki.SubjectKeyID([]byte{0x0c, 0x0a})
	ca := testpki.Issue(t, "CRL Signer CA", nil, testpki.CA(), ski)
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	revocationList, err := crl.ParseCRL(ca.RevocationList(t, &cryptox509.RevocationList{
		ThisUpdate: now,
		NextUpdate: now.Add(30 * 24 * time.Hour),
	}))
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	impostor := testpki.Issue(t, "CRL Signer CA", nil, testpki.Serial(99), ski)
	return revocationList, impostor.Cert, ca.Cert
}

func TestCRLSignedBy_chainOrder_table(t *testing.T) {
	revocationList, impostor, ca := signedCRLWithCA(t)
	crlInfo := &crl.Info{CRL: revocationList}
	op := CRLSignedBy{}

	tests := []struct {
		name   string
		chain  []*x509.Certificate
		wantOK bool
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
			name:   "unrelated CA only: signer cannot be verified",
			chain:  []*x509.Certificate{{Subject: pkix.Name{CommonName: "Other"}, SerialNumber: big.NewInt(1), IsCA: true}},
			wantOK: false,
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
