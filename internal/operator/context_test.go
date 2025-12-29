package operator

import (
	"testing"
	"time"

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
