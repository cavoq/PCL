package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
	sharedzcrypto "github.com/cavoq/PCL/internal/zcrypto"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestPathLenValidName(t *testing.T) {
	op := PathLenValid{}
	if op.Name() != "pathLenValid" {
		t.Errorf("expected pathLenValid, got %s", op.Name())
	}
}

func TestPathLenValidNilContext(t *testing.T) {
	op := PathLenValid{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestPathLenValidNilCert(t *testing.T) {
	op := PathLenValid{}
	ctx := &EvaluationContext{
		Cert: &cert.Info{
			Type: "root",
			Cert: nil,
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil cert should return false")
	}
}

func TestValidityPeriodDaysName(t *testing.T) {
	op := ValidityPeriodDays{}
	if op.Name() != "validityDays" {
		t.Errorf("expected validityDays, got %s", op.Name())
	}
}

func TestValidityPeriodDaysNilContext(t *testing.T) {
	op := ValidityPeriodDays{}
	got, err := op.Evaluate(nil, nil, []any{1, 365})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestSerialNumberUniqueName(t *testing.T) {
	op := SerialNumberUnique{}
	if op.Name() != "serialNumberUnique" {
		t.Errorf("expected serialNumberUnique, got %s", op.Name())
	}
}

func TestSerialNumberUniqueNilContext(t *testing.T) {
	op := SerialNumberUnique{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Error("nil context should return false")
	}
}

func TestNoUnknownCriticalExtensionsUsesTargetOID(t *testing.T) {
	buildTarget := func(name string, objectID zasn1.ObjectIdentifier) *node.Node {
		target := node.New(name, nil)
		target.Children["extensions"] = sharedzcrypto.BuildExtensions([]pkix.Extension{{
			Id:       objectID,
			Critical: true,
		}})
		return target
	}

	op := NoUnknownCriticalExtensions{}
	tests := []struct {
		name   string
		target *node.Node
		ctx    *EvaluationContext
		want   bool
	}{
		{
			name:   "known certificate extension",
			target: buildTarget("certificate", zasn1.ObjectIdentifier{2, 5, 29, 17}),
			want:   true,
		},
		{
			name:   "unknown certificate extension",
			target: buildTarget("certificate", zasn1.ObjectIdentifier{1, 2, 3, 4}),
		},
		{
			name:   "known CRL extension with friendly alias",
			target: buildTarget("crl", zasn1.ObjectIdentifier{2, 5, 29, 28}),
			ctx:    &EvaluationContext{Cert: &cert.Info{Cert: &x509.Certificate{}}},
			want:   true,
		},
		{
			name:   "unknown CRL extension",
			target: buildTarget("crl", zasn1.ObjectIdentifier{1, 2, 3, 4}),
			ctx:    &EvaluationContext{Cert: &cert.Info{Cert: &x509.Certificate{}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.target, tt.ctx, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("NoUnknownCriticalExtensions = %v, want %v", got, tt.want)
			}
		})
	}
}
