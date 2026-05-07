package linter

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/operator"
)

func TestEvaluateChainWithEmptyChain(t *testing.T) {
	evalCtx := EvaluationContext{
		Policies: nil,
		Registry: operator.DefaultRegistry(),
		CRLs:     nil,
		OCSPs:    nil,
		Chain:    []*cert.Info{},
	}

	results := evaluateChain(evalCtx)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty chain, got %d", len(results))
	}
}

func TestEvaluateCRLOnlyWithEmptyCRLs(t *testing.T) {
	results := evaluateCRLOnly(nil, operator.DefaultRegistry(), nil, nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty CRLs, got %d", len(results))
	}
}

func TestEvaluateOCSPOnlyWithEmptyOCSPs(t *testing.T) {
	results := evaluateOCSPOnly(nil, operator.DefaultRegistry(), nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty OCSPs, got %d", len(results))
	}
}

func TestExtractCertsFromInfoEmpty(t *testing.T) {
	certs := extractCertsFromInfo(nil)
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for nil input, got %d", len(certs))
	}

	certs = extractCertsFromInfo([]*cert.Info{})
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for empty slice, got %d", len(certs))
	}
}

func TestExtractCertsFromInfoWithNilCert(t *testing.T) {
	infos := []*cert.Info{
		{Cert: nil},
		{Cert: nil, FilePath: "test.pem"},
	}
	certs := extractCertsFromInfo(infos)
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for nil certs in info, got %d", len(certs))
	}
}

func TestEvaluationContextDefaults(t *testing.T) {
	evalCtx := EvaluationContext{}

	// Verify default values
	if evalCtx.Registry == nil {
		// Registry should be set when actually used
		t.Log("Registry is nil in default context (expected)")
	}
	if evalCtx.Chain != nil {
		t.Errorf("expected nil Chain in default context")
	}
	if evalCtx.CRLs != nil {
		t.Errorf("expected nil CRLs in default context")
	}
	if evalCtx.OCSPs != nil {
		t.Errorf("expected nil OCSPs in default context")
	}
}
