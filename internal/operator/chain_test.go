package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
)

func TestSignedByName(t *testing.T) {
	op := SignedBy{}
	if op.Name() != "signedBy" {
		t.Error("wrong name")
	}
}

func TestSignedByNilContext(t *testing.T) {
	op := SignedBy{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestSignedByNilCert(t *testing.T) {
	op := SignedBy{}
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

func TestBytesEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{"equal", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"not equal", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{"different length", []byte{1, 2}, []byte{1, 2, 3}, false},
		{"both empty", []byte{}, []byte{}, true},
		{"one empty", []byte{1}, []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bytesEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("bytesEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignedByRootSelfCheck(t *testing.T) {
	op := SignedBy{}
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
