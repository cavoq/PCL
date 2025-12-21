package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/zmap/zcrypto/x509"
)

func TestEKUContainsName(t *testing.T) {
	op := EKUContains{}
	if op.Name() != "ekuContains" {
		t.Errorf("expected ekuContains, got %s", op.Name())
	}
}

func TestEKUContainsNilContext(t *testing.T) {
	op := EKUContains{}
	got, err := op.Evaluate(nil, nil, []any{"serverAuth"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestEKUNotContainsName(t *testing.T) {
	op := EKUNotContains{}
	if op.Name() != "ekuNotContains" {
		t.Errorf("expected ekuNotContains, got %s", op.Name())
	}
}

func TestEKUServerAuthName(t *testing.T) {
	op := EKUServerAuth{}
	if op.Name() != "ekuServerAuth" {
		t.Errorf("expected ekuServerAuth, got %s", op.Name())
	}
}

func TestEKUServerAuthNilContext(t *testing.T) {
	op := EKUServerAuth{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestEKUClientAuthName(t *testing.T) {
	op := EKUClientAuth{}
	if op.Name() != "ekuClientAuth" {
		t.Errorf("expected ekuClientAuth, got %s", op.Name())
	}
}

func TestEKUClientAuthNilContext(t *testing.T) {
	op := EKUClientAuth{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestParseEKU(t *testing.T) {
	tests := []struct {
		name string
		want x509.ExtKeyUsage
	}{
		{"any", x509.ExtKeyUsageAny},
		{"serverAuth", x509.ExtKeyUsageServerAuth},
		{"clientAuth", x509.ExtKeyUsageClientAuth},
		{"codeSigning", x509.ExtKeyUsageCodeSigning},
		{"emailProtection", x509.ExtKeyUsageEmailProtection},
		{"timeStamping", x509.ExtKeyUsageTimeStamping},
		{"ocspSigning", x509.ExtKeyUsageOcspSigning},
		{"unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEKU(tt.name)
			if got != tt.want {
				t.Errorf("parseEKU(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestEKUContainsNoOperands(t *testing.T) {
	op := EKUContains{}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: nil,
		},
	}
	got, _ := op.Evaluate(nil, ctx, []any{})
	if got != false {
		t.Error("no operands should return false")
	}
}

func TestEKUNotContainsNoOperands(t *testing.T) {
	op := EKUNotContains{}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Cert: nil,
		},
	}
	got, _ := op.Evaluate(nil, ctx, []any{})
	// With nil cert, should return false
	if got != false {
		t.Error("nil cert should return false")
	}
}
