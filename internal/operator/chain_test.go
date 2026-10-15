package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
)

func TestSignatureValidNilContext(t *testing.T) {
	op := SignatureValid{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestSignatureValidNilCert(t *testing.T) {
	op := SignatureValid{}
	ctx := &EvaluationContext{Cert: nil}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil cert should return false")
	}
}

func TestIssuedByNilContext(t *testing.T) {
	op := IssuedBy{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestAKIMatchesSKINilContext(t *testing.T) {
	op := AKIMatchesSKI{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestSignatureValidRootSelfCheck(t *testing.T) {
	op := SignatureValid{}
	ctx := &EvaluationContext{
		Input: Input{Kind: "root"},
		Cert:  &cert.Info{},
	}
	got, _ := op.Evaluate(nil, ctx, nil)
	if got != false {
		t.Error("nil cert in root should return false")
	}
}

func TestIssuedByChainBoundary(t *testing.T) {
	op := IssuedBy{}
	ctx := &EvaluationContext{
		Input: Input{Kind: "leaf"},
		Cert:  &cert.Info{},
		Chain: []*cert.Info{},
	}
	got, _ := op.Evaluate(nil, ctx, nil)
	if got != false {
		t.Error("should return false when no issuer in chain")
	}
}

func TestAKIMatchesSKINoAKI(t *testing.T) {
	op := AKIMatchesSKI{}
	n := node.New("test", nil)
	ctx := &EvaluationContext{
		Input: Input{Kind: "leaf"},
		Cert:  &cert.Info{},
	}
	got, _ := op.Evaluate(n, ctx, nil)
	if got != false {
		t.Error("nil cert should return false")
	}
}
