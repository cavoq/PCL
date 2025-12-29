package operator

import (
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
)

func TestNewEvaluationContext_Basic(t *testing.T) {
	root := node.New("root", nil)
	certInfo := &cert.Info{Type: "leaf"}
	chain := []*cert.Info{certInfo}

	ctx := NewEvaluationContext(root, certInfo, chain)

	if ctx.Root != root {
		t.Error("Root should be set")
	}
	if ctx.Cert != certInfo {
		t.Error("Cert should be set")
	}
	if len(ctx.Chain) != 1 {
		t.Errorf("expected chain length 1, got %d", len(ctx.Chain))
	}
	if ctx.Now.IsZero() {
		t.Error("Now should be set to current time")
	}
	if ctx.CRLs != nil {
		t.Error("CRLs should be nil by default")
	}
	if ctx.OCSPs != nil {
		t.Error("OCSPs should be nil by default")
	}
}

func TestNewEvaluationContext_WithCRLs(t *testing.T) {
	root := node.New("root", nil)
	certInfo := &cert.Info{Type: "leaf"}
	chain := []*cert.Info{certInfo}

	crls := []*crl.Info{
		{Hash: "abc123"},
		{Hash: "def456"},
	}

	ctx := NewEvaluationContext(root, certInfo, chain, WithCRLs(crls))

	if len(ctx.CRLs) != 2 {
		t.Errorf("expected 2 CRLs, got %d", len(ctx.CRLs))
	}
	if ctx.CRLs[0].Hash != "abc123" {
		t.Errorf("expected first CRL hash 'abc123', got %q", ctx.CRLs[0].Hash)
	}
}

func TestNewEvaluationContext_WithOCSPs(t *testing.T) {
	root := node.New("root", nil)
	certInfo := &cert.Info{Type: "leaf"}
	chain := []*cert.Info{certInfo}

	ocsps := []*ocsp.Info{
		{Hash: "ocsp1"},
	}

	ctx := NewEvaluationContext(root, certInfo, chain, WithOCSPs(ocsps))

	if len(ctx.OCSPs) != 1 {
		t.Errorf("expected 1 OCSP, got %d", len(ctx.OCSPs))
	}
	if ctx.OCSPs[0].Hash != "ocsp1" {
		t.Errorf("expected OCSP hash 'ocsp1', got %q", ctx.OCSPs[0].Hash)
	}
}

func TestNewEvaluationContext_MultipleOptions(t *testing.T) {
	root := node.New("root", nil)
	certInfo := &cert.Info{Type: "leaf"}
	chain := []*cert.Info{certInfo}

	crls := []*crl.Info{{Hash: "crl1"}}
	ocsps := []*ocsp.Info{{Hash: "ocsp1"}}

	ctx := NewEvaluationContext(root, certInfo, chain, WithCRLs(crls), WithOCSPs(ocsps))

	if len(ctx.CRLs) != 1 {
		t.Errorf("expected 1 CRL, got %d", len(ctx.CRLs))
	}
	if len(ctx.OCSPs) != 1 {
		t.Errorf("expected 1 OCSP, got %d", len(ctx.OCSPs))
	}
}

func TestNewEvaluationContext_NilValues(t *testing.T) {
	ctx := NewEvaluationContext(nil, nil, nil)

	if ctx.Root != nil {
		t.Error("Root should be nil")
	}
	if ctx.Cert != nil {
		t.Error("Cert should be nil")
	}
	if ctx.Chain != nil {
		t.Error("Chain should be nil")
	}
	// Now should still be set
	if ctx.Now.IsZero() {
		t.Error("Now should be set even with nil values")
	}
}

func TestNewEvaluationContext_NowIsRecent(t *testing.T) {
	before := time.Now()
	ctx := NewEvaluationContext(nil, nil, nil)
	after := time.Now()

	if ctx.Now.Before(before) || ctx.Now.After(after) {
		t.Error("Now should be set to current time during context creation")
	}
}

func TestWithCRLs_NilSlice(t *testing.T) {
	root := node.New("root", nil)
	ctx := NewEvaluationContext(root, nil, nil, WithCRLs(nil))

	if ctx.CRLs != nil {
		t.Error("CRLs should be nil when passed nil")
	}
}

func TestWithOCSPs_NilSlice(t *testing.T) {
	root := node.New("root", nil)
	ctx := NewEvaluationContext(root, nil, nil, WithOCSPs(nil))

	if ctx.OCSPs != nil {
		t.Error("OCSPs should be nil when passed nil")
	}
}

func TestWithCRLs_EmptySlice(t *testing.T) {
	root := node.New("root", nil)
	crls := []*crl.Info{}
	ctx := NewEvaluationContext(root, nil, nil, WithCRLs(crls))

	if ctx.CRLs == nil {
		t.Error("CRLs should not be nil when passed empty slice")
	}
	if len(ctx.CRLs) != 0 {
		t.Errorf("expected 0 CRLs, got %d", len(ctx.CRLs))
	}
}

func TestHasCert_NilContext(t *testing.T) {
	var ctx *EvaluationContext
	if ctx.HasCert() {
		t.Error("nil context should return false")
	}
}

func TestHasCert_NilCert(t *testing.T) {
	ctx := &EvaluationContext{}
	if ctx.HasCert() {
		t.Error("nil Cert should return false")
	}
}

func TestHasCert_NilCertCert(t *testing.T) {
	ctx := &EvaluationContext{Cert: &cert.Info{}}
	if ctx.HasCert() {
		t.Error("nil Cert.Cert should return false")
	}
}

func TestHasCert_Valid(t *testing.T) {
	ctx := &EvaluationContext{Cert: &cert.Info{Cert: &x509.Certificate{}}}
	if !ctx.HasCert() {
		t.Error("valid cert should return true")
	}
}

func TestHasChain_NilContext(t *testing.T) {
	var ctx *EvaluationContext
	if ctx.HasChain() {
		t.Error("nil context should return false")
	}
}

func TestHasChain_EmptyChain(t *testing.T) {
	ctx := &EvaluationContext{Chain: []*cert.Info{}}
	if ctx.HasChain() {
		t.Error("empty chain should return false")
	}
}

func TestHasChain_Valid(t *testing.T) {
	ctx := &EvaluationContext{Chain: []*cert.Info{{}}}
	if !ctx.HasChain() {
		t.Error("non-empty chain should return true")
	}
}

func TestHasCRLs_NilContext(t *testing.T) {
	var ctx *EvaluationContext
	if ctx.HasCRLs() {
		t.Error("nil context should return false")
	}
}

func TestHasCRLs_EmptyCRLs(t *testing.T) {
	ctx := &EvaluationContext{CRLs: []*crl.Info{}}
	if ctx.HasCRLs() {
		t.Error("empty CRLs should return false")
	}
}

func TestHasCRLs_Valid(t *testing.T) {
	ctx := &EvaluationContext{CRLs: []*crl.Info{{}}}
	if !ctx.HasCRLs() {
		t.Error("non-empty CRLs should return true")
	}
}

func TestHasOCSPs_NilContext(t *testing.T) {
	var ctx *EvaluationContext
	if ctx.HasOCSPs() {
		t.Error("nil context should return false")
	}
}

func TestHasOCSPs_EmptyOCSPs(t *testing.T) {
	ctx := &EvaluationContext{OCSPs: []*ocsp.Info{}}
	if ctx.HasOCSPs() {
		t.Error("empty OCSPs should return false")
	}
}

func TestHasOCSPs_Valid(t *testing.T) {
	ctx := &EvaluationContext{OCSPs: []*ocsp.Info{{}}}
	if !ctx.HasOCSPs() {
		t.Error("non-empty OCSPs should return true")
	}
}
