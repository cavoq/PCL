package operator

import (
	"testing"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/cert"
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
		ok   bool
	}{
		{"any", x509.ExtKeyUsageAny, true},
		{"serverAuth", x509.ExtKeyUsageServerAuth, true},
		{"clientAuth", x509.ExtKeyUsageClientAuth, true},
		{"codeSigning", x509.ExtKeyUsageCodeSigning, true},
		{"emailProtection", x509.ExtKeyUsageEmailProtection, true},
		{"timeStamping", x509.ExtKeyUsageTimeStamping, true},
		{"ocspSigning", x509.ExtKeyUsageOcspSigning, true},
		{"unknown", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseEKU(tt.name)
			if got != tt.want || ok != tt.ok {
				t.Errorf("parseEKU(%s) = (%v, %v), want (%v, %v)", tt.name, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestEKUContainsHandlesAnyUsage(t *testing.T) {
	ctx := &EvaluationContext{Cert: &cert.Info{Cert: &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}}}

	contains, err := (EKUContains{}).Evaluate(nil, ctx, []any{"any"})
	if err != nil {
		t.Fatalf("EKUContains returned error: %v", err)
	}
	if !contains {
		t.Fatal("EKUContains did not recognize ExtKeyUsageAny")
	}

	notContains, err := (EKUNotContains{}).Evaluate(nil, ctx, []any{"any"})
	if err != nil {
		t.Fatalf("EKUNotContains returned error: %v", err)
	}
	if notContains {
		t.Fatal("EKUNotContains did not recognize ExtKeyUsageAny")
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
