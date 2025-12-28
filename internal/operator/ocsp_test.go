package operator

import (
	"math/big"
	"testing"
	"time"

	stdocsp "golang.org/x/crypto/ocsp"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/ocsp"
)

func TestOCSPValidName(t *testing.T) {
	op := OCSPValid{}
	if op.Name() != "ocspValid" {
		t.Error("wrong name")
	}
}

func TestOCSPValidNilContext(t *testing.T) {
	op := OCSPValid{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil context should return false")
	}
}

func TestOCSPValidNoOCSPs(t *testing.T) {
	op := OCSPValid{}
	ctx := &EvaluationContext{OCSPs: nil}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("empty OCSPs should return false")
	}
}

func TestOCSPValidNoChain(t *testing.T) {
	op := OCSPValid{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		OCSPs: []*ocsp.Info{{
			Response: &stdocsp.Response{
				ThisUpdate: now.Add(-time.Hour),
				NextUpdate: now.Add(time.Hour),
			},
		}},
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

func TestOCSPValidBeforeThisUpdate(t *testing.T) {
	op := OCSPValid{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		OCSPs: []*ocsp.Info{{
			Response: &stdocsp.Response{
				ThisUpdate: now.Add(time.Hour),
				NextUpdate: now.Add(2 * time.Hour),
			},
		}},
		Chain: []*cert.Info{{}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("OCSP before thisUpdate should be invalid")
	}
}

func TestOCSPValidAfterNextUpdate(t *testing.T) {
	op := OCSPValid{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		OCSPs: []*ocsp.Info{{
			Response: &stdocsp.Response{
				ThisUpdate: now.Add(-2 * time.Hour),
				NextUpdate: now.Add(-time.Hour),
			},
		}},
		Chain: []*cert.Info{{}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("OCSP after nextUpdate should be invalid")
	}
}

func TestOCSPValidNilResponseInInfo(t *testing.T) {
	op := OCSPValid{}
	now := time.Now()
	ctx := &EvaluationContext{
		Now: now,
		OCSPs: []*ocsp.Info{
			{Response: nil},
		},
		Chain: []*cert.Info{{}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("should skip nil responses")
	}
}

func TestNotRevokedOCSPName(t *testing.T) {
	op := NotRevokedOCSP{}
	if op.Name() != "notRevokedOCSP" {
		t.Error("wrong name")
	}
}

func TestNotRevokedOCSPNilContext(t *testing.T) {
	op := NotRevokedOCSP{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil context should return false")
	}
}

func TestNotRevokedOCSPNilCert(t *testing.T) {
	op := NotRevokedOCSP{}
	ctx := &EvaluationContext{Cert: nil}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil cert should return false")
	}
}

func TestNotRevokedOCSPNoOCSPs(t *testing.T) {
	op := NotRevokedOCSP{}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: big.NewInt(123),
			},
		},
		OCSPs: nil,
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("no OCSPs should return true (not revoked)")
	}
}

func TestNotRevokedOCSPCertNotRevoked(t *testing.T) {
	op := NotRevokedOCSP{}
	serial := big.NewInt(123)
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: serial,
			},
		},
		OCSPs: []*ocsp.Info{{
			Response: &stdocsp.Response{
				SerialNumber: serial,
				Status:       stdocsp.Good,
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("good status should return true")
	}
}

func TestNotRevokedOCSPCertRevoked(t *testing.T) {
	op := NotRevokedOCSP{}
	serial := big.NewInt(123)
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: serial,
			},
		},
		OCSPs: []*ocsp.Info{{
			Response: &stdocsp.Response{
				SerialNumber: serial,
				Status:       stdocsp.Revoked,
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("revoked status should return false")
	}
}

func TestNotRevokedOCSPDifferentSerial(t *testing.T) {
	op := NotRevokedOCSP{}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: big.NewInt(123),
			},
		},
		OCSPs: []*ocsp.Info{{
			Response: &stdocsp.Response{
				SerialNumber: big.NewInt(456),
				Status:       stdocsp.Revoked,
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("different serial should not affect cert")
	}
}

func TestOCSPGoodName(t *testing.T) {
	op := OCSPGood{}
	if op.Name() != "ocspGood" {
		t.Error("wrong name")
	}
}

func TestOCSPGoodNilContext(t *testing.T) {
	op := OCSPGood{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil context should return false")
	}
}

func TestOCSPGoodNoOCSPs(t *testing.T) {
	op := OCSPGood{}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: big.NewInt(123),
			},
		},
		OCSPs: nil,
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("no OCSPs should return false (requires explicit Good)")
	}
}

func TestOCSPGoodWithGoodStatus(t *testing.T) {
	op := OCSPGood{}
	serial := big.NewInt(123)
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: serial,
			},
		},
		OCSPs: []*ocsp.Info{{
			Response: &stdocsp.Response{
				SerialNumber: serial,
				Status:       stdocsp.Good,
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("good status should return true")
	}
}

func TestOCSPGoodWithRevokedStatus(t *testing.T) {
	op := OCSPGood{}
	serial := big.NewInt(123)
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: serial,
			},
		},
		OCSPs: []*ocsp.Info{{
			Response: &stdocsp.Response{
				SerialNumber: serial,
				Status:       stdocsp.Revoked,
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("revoked status should return false")
	}
}

func TestOCSPGoodWithUnknownStatus(t *testing.T) {
	op := OCSPGood{}
	serial := big.NewInt(123)
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: serial,
			},
		},
		OCSPs: []*ocsp.Info{{
			Response: &stdocsp.Response{
				SerialNumber: serial,
				Status:       stdocsp.Unknown,
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("unknown status should return false")
	}
}

func TestOCSPGoodDifferentSerial(t *testing.T) {
	op := OCSPGood{}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: &x509.Certificate{
				SerialNumber: big.NewInt(123),
			},
		},
		OCSPs: []*ocsp.Info{{
			Response: &stdocsp.Response{
				SerialNumber: big.NewInt(456),
				Status:       stdocsp.Good,
			},
		}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("different serial should not match")
	}
}
