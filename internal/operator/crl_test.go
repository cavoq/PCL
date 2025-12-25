package operator

import (
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
)

func TestCRLValidName(t *testing.T) {
	op := CRLValid{}
	if op.Name() != "crlValid" {
		t.Error("wrong name")
	}
}

func TestCRLValidNilContext(t *testing.T) {
	op := CRLValid{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil context should return false")
	}
}

func TestCRLValidNoCRLs(t *testing.T) {
	op := CRLValid{}
	ctx := &EvaluationContext{CRLs: nil}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("empty CRLs should return false")
	}
}

func TestCRLValidWithinWindow(t *testing.T) {
	op := CRLValid{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		CRLs: []*crl.Info{{
			CRL: &x509.RevocationList{
				ThisUpdate: now.Add(-time.Hour),
				NextUpdate: now.Add(time.Hour),
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("CRL within window should be valid")
	}
}

func TestCRLValidBeforeThisUpdate(t *testing.T) {
	op := CRLValid{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		CRLs: []*crl.Info{{
			CRL: &x509.RevocationList{
				ThisUpdate: now.Add(time.Hour),
				NextUpdate: now.Add(2 * time.Hour),
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("CRL before thisUpdate should be invalid")
	}
}

func TestCRLValidAfterNextUpdate(t *testing.T) {
	op := CRLValid{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		CRLs: []*crl.Info{{
			CRL: &x509.RevocationList{
				ThisUpdate: now.Add(-2 * time.Hour),
				NextUpdate: now.Add(-time.Hour),
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("CRL after nextUpdate should be invalid")
	}
}

func TestCRLValidNoNextUpdate(t *testing.T) {
	op := CRLValid{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		CRLs: []*crl.Info{{
			CRL: &x509.RevocationList{
				ThisUpdate: now.Add(-time.Hour),
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("CRL without nextUpdate after thisUpdate should be valid")
	}
}

func TestCRLValidNilCRLInInfo(t *testing.T) {
	op := CRLValid{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		CRLs: []*crl.Info{{
			CRL: nil,
		}, {
			CRL: &x509.RevocationList{
				ThisUpdate: now.Add(-time.Hour),
				NextUpdate: now.Add(time.Hour),
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("should skip nil CRL and validate others")
	}
}

func TestCRLNotExpiredName(t *testing.T) {
	op := CRLNotExpired{}
	if op.Name() != "crlNotExpired" {
		t.Error("wrong name")
	}
}

func TestCRLNotExpiredNilContext(t *testing.T) {
	op := CRLNotExpired{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil context should return false")
	}
}

func TestCRLNotExpiredValid(t *testing.T) {
	op := CRLNotExpired{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		CRLs: []*crl.Info{{
			CRL: &x509.RevocationList{
				NextUpdate: now.Add(time.Hour),
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("CRL not expired should return true")
	}
}

func TestCRLNotExpiredExpired(t *testing.T) {
	op := CRLNotExpired{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		CRLs: []*crl.Info{{
			CRL: &x509.RevocationList{
				NextUpdate: now.Add(-time.Hour),
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("expired CRL should return false")
	}
}

func TestCRLSignedByName(t *testing.T) {
	op := CRLSignedBy{}
	if op.Name() != "crlSignedBy" {
		t.Error("wrong name")
	}
}

func TestCRLSignedByNilContext(t *testing.T) {
	op := CRLSignedBy{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil context should return false")
	}
}

func TestCRLSignedByNoCRLs(t *testing.T) {
	op := CRLSignedBy{}
	ctx := &EvaluationContext{
		CRLs:  nil,
		Chain: []*cert.Info{{}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("no CRLs should return false")
	}
}

func TestCRLSignedByNoChain(t *testing.T) {
	op := CRLSignedBy{}
	ctx := &EvaluationContext{
		CRLs:  []*crl.Info{{}},
		Chain: nil,
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("no chain should return false")
	}
}

func TestCRLSignedByIssuerMismatch(t *testing.T) {
	op := CRLSignedBy{}
	ctx := &EvaluationContext{
		CRLs: []*crl.Info{{
			CRL: &x509.RevocationList{
				Issuer: pkix.Name{CommonName: "CRL Issuer"},
			},
		}},
		Chain: []*cert.Info{{
			Cert: &x509.Certificate{
				Subject: pkix.Name{CommonName: "Different CA"},
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("issuer mismatch should return false")
	}
}

func TestNotRevokedName(t *testing.T) {
	op := NotRevoked{}
	if op.Name() != "notRevoked" {
		t.Error("wrong name")
	}
}

func TestNotRevokedNilContext(t *testing.T) {
	op := NotRevoked{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil context should return false")
	}
}

func TestNotRevokedNilCert(t *testing.T) {
	op := NotRevoked{}
	ctx := &EvaluationContext{Cert: nil}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil cert should return false")
	}
}

func TestNotRevokedNoCRLs(t *testing.T) {
	op := NotRevoked{}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: big.NewInt(123),
				Issuer:       pkix.Name{CommonName: "Test CA"},
			},
		},
		CRLs: nil,
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("no CRLs should return true (not revoked)")
	}
}

func TestNotRevokedCertNotInCRL(t *testing.T) {
	op := NotRevoked{}
	issuer := pkix.Name{CommonName: "Test CA"}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: big.NewInt(123),
				Issuer:       issuer,
			},
		},
		CRLs: []*crl.Info{{
			CRL: &x509.RevocationList{
				Issuer: issuer,
				RevokedCertificates: []x509.RevokedCertificate{
					{SerialNumber: big.NewInt(456)},
				},
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("cert not in CRL should return true")
	}
}

func TestNotRevokedCertInCRL(t *testing.T) {
	op := NotRevoked{}
	issuer := pkix.Name{CommonName: "Test CA"}
	serial := big.NewInt(123)
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: serial,
				Issuer:       issuer,
			},
		},
		CRLs: []*crl.Info{{
			CRL: &x509.RevocationList{
				Issuer: issuer,
				RevokedCertificates: []x509.RevokedCertificate{
					{SerialNumber: serial},
				},
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("revoked cert should return false")
	}
}

func TestNotRevokedDifferentIssuer(t *testing.T) {
	op := NotRevoked{}
	serial := big.NewInt(123)
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: serial,
				Issuer:       pkix.Name{CommonName: "CA A"},
			},
		},
		CRLs: []*crl.Info{{
			CRL: &x509.RevocationList{
				Issuer: pkix.Name{CommonName: "CA B"},
				RevokedCertificates: []x509.RevokedCertificate{
					{SerialNumber: serial},
				},
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("CRL from different issuer should not affect cert")
	}
}

func TestNotRevokedNilCRLInInfo(t *testing.T) {
	op := NotRevoked{}
	issuer := pkix.Name{CommonName: "Test CA"}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: big.NewInt(123),
				Issuer:       issuer,
			},
		},
		CRLs: []*crl.Info{
			{CRL: nil},
			{
				CRL: &x509.RevocationList{
					Issuer:              issuer,
					RevokedCertificates: []x509.RevokedCertificate{},
				},
			},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("should skip nil CRL and check others")
	}
}
