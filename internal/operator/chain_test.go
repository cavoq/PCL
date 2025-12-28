package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
)

func TestSignatureValidName(t *testing.T) {
	op := SignatureValid{}
	if op.Name() != "signatureValid" {
		t.Error("wrong name")
	}
}

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

func TestIssuedByName(t *testing.T) {
	op := IssuedBy{}
	if op.Name() != "issuedBy" {
		t.Error("wrong name")
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

func TestAKIMatchesSKIName(t *testing.T) {
	op := AKIMatchesSKI{}
	if op.Name() != "akiMatchesSki" {
		t.Error("wrong name")
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
		Cert: &cert.Info{
			Type:     "root",
			Position: 0,
			Cert:     nil,
		},
	}
	got, _ := op.Evaluate(nil, ctx, nil)
	if got != false {
		t.Error("nil cert in root should return false")
	}
}

func TestIssuedByChainBoundary(t *testing.T) {
	op := IssuedBy{}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Type:     "leaf",
			Position: 0,
			Cert:     nil,
		},
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
		Cert: &cert.Info{
			Type:     "leaf",
			Position: 0,
			Cert:     nil,
		},
	}
	got, _ := op.Evaluate(n, ctx, nil)
	if got != false {
		t.Error("nil cert should return false")
	}
}
