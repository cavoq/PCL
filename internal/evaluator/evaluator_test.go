package evaluator

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/operator"
)

func TestChainWithEmptyChain(t *testing.T) {
	evalCtx := Context{
		Policies: nil,
		Registry: operator.DefaultRegistry(),
		CRLs:     nil,
		OCSPs:    nil,
		Chain:    []*cert.Info{},
	}

	results := Chain(evalCtx)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty chain, got %d", len(results))
	}
}

func TestCRLOnlyWithEmptyCRLs(t *testing.T) {
	results := CRLOnly(nil, operator.DefaultRegistry(), nil, nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty CRLs, got %d", len(results))
	}
}

func TestOCSPOnlyWithEmptyOCSPs(t *testing.T) {
	results := OCSPOnly(nil, operator.DefaultRegistry(), nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty OCSPs, got %d", len(results))
	}
}

func TestExtractCertsFromInfoEmpty(t *testing.T) {
	certs := ExtractCertsFromInfo(nil)
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for nil input, got %d", len(certs))
	}

	certs = ExtractCertsFromInfo([]*cert.Info{})
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for empty slice, got %d", len(certs))
	}
}

func TestExtractCertsFromInfoWithNilCert(t *testing.T) {
	infos := []*cert.Info{
		{Cert: nil},
		{Cert: nil, FilePath: "test.pem"},
	}
	certs := ExtractCertsFromInfo(infos)
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for nil certs in info, got %d", len(certs))
	}
}

func TestContextDefaults(t *testing.T) {
	evalCtx := Context{}

	if evalCtx.Registry == nil {
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
