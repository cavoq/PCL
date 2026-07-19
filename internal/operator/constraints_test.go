package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
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

func TestNoUnknownCriticalExtensionsUsesProcessedRegistry(t *testing.T) {
	buildTarget := func(name string, objectID zasn1.ObjectIdentifier, malformed bool) *node.Node {
		target := node.New(name, nil)
		target.Children["extensions"] = sharedzcrypto.BuildExtensions([]pkix.Extension{{
			Id:       objectID,
			Critical: true,
		}})
		if malformed {
			target.Children["extensions"].Children[objectID.String()].Children["malformed"] = node.New("malformed", true)
		}
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
			name:   "processable certificate extension",
			target: buildTarget("certificate", zasn1.ObjectIdentifier{2, 5, 29, 17}, false),
			want:   true,
		},
		{
			name:   "newly processable certificate extension",
			target: buildTarget("certificate", zasn1.ObjectIdentifier{2, 5, 29, 33}, false),
			want:   true,
		},
		{
			name:   "known but unprocessed certificate extension",
			target: buildTarget("certificate", zasn1.ObjectIdentifier{2, 5, 29, 16}, false),
		},
		{
			name:   "malformed processable certificate extension",
			target: buildTarget("certificate", zasn1.ObjectIdentifier{2, 5, 29, 17}, true),
		},
		{
			name:   "unknown certificate extension",
			target: buildTarget("certificate", zasn1.ObjectIdentifier{1, 2, 3, 4}, false),
		},
		{
			name:   "known CRL extension is deferred to P3",
			target: buildTarget("crl", zasn1.ObjectIdentifier{2, 5, 29, 20}, false),
			ctx:    &EvaluationContext{Cert: &cert.Info{Cert: &x509.Certificate{}}},
		},
		{
			name:   "known but P3-only CRL extension",
			target: buildTarget("crl", zasn1.ObjectIdentifier{2, 5, 29, 28}, false),
			ctx:    &EvaluationContext{Cert: &cert.Info{Cert: &x509.Certificate{}}},
		},
		{
			name:   "unknown CRL extension",
			target: buildTarget("crl", zasn1.ObjectIdentifier{1, 2, 3, 4}, false),
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

	t.Run("duplicate extension OID fails before criticality lookup", func(t *testing.T) {
		target := node.New("certificate", nil)
		target.Children["extensions"] = sharedzcrypto.BuildExtensions([]pkix.Extension{
			{Id: zasn1.ObjectIdentifier{2, 5, 29, 15}, Critical: false},
			{Id: zasn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true},
		})
		got, err := op.Evaluate(target, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got {
			t.Fatal("NoUnknownCriticalExtensions accepted duplicate extension OIDs")
		}
	})

	t.Run("critical CRL entry extension fails closed pending P3", func(t *testing.T) {
		target := node.New("crl", nil)
		revoked := node.New("revokedCertificates", nil)
		entry := node.New("0", nil)
		entry.Children["extensions"] = sharedzcrypto.BuildExtensions([]pkix.Extension{{
			Id:       zasn1.ObjectIdentifier{2, 5, 29, 21},
			Critical: true,
		}})
		revoked.Children["0"] = entry
		target.Children["revokedCertificates"] = revoked

		got, err := op.Evaluate(target, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got {
			t.Fatal("NoUnknownCriticalExtensions accepted a critical CRL entry extension")
		}
	})

	t.Run("noncritical CRL entry extension remains profile-visible", func(t *testing.T) {
		target := node.New("crl", nil)
		revoked := node.New("revokedCertificates", nil)
		entry := node.New("0", nil)
		entry.Children["extensions"] = sharedzcrypto.BuildExtensions([]pkix.Extension{{
			Id: zasn1.ObjectIdentifier{2, 5, 29, 21},
		}})
		revoked.Children["0"] = entry
		target.Children["revokedCertificates"] = revoked

		got, err := op.Evaluate(target, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got {
			t.Fatal("NoUnknownCriticalExtensions rejected a noncritical CRL entry extension")
		}
	})
}

func TestNoUnknownCriticalExtensionsRejectsUnprocessedExtensionContent(t *testing.T) {
	tests := []struct {
		name       string
		identifier zasn1.ObjectIdentifier
		value      []byte
	}{
		{
			name:       "unsupported Name Constraints form",
			identifier: zasn1.ObjectIdentifier{2, 5, 29, 30},
			value: []byte{
				0x30, 0x08, 0xa0, 0x06, 0x30, 0x04, 0x88, 0x02, 0x2a, 0x03,
			},
		},
		{
			name:       "unknown Certificate Policies qualifier",
			identifier: zasn1.ObjectIdentifier{2, 5, 29, 32},
			value: []byte{
				0x30, 0x10, 0x30, 0x0e, 0x06, 0x02, 0x2a, 0x03,
				0x30, 0x08, 0x30, 0x06, 0x06, 0x02, 0x2a, 0x04,
				0x05, 0x00,
			},
		},
	}

	op := NoUnknownCriticalExtensions{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificate := &x509.Certificate{Extensions: []pkix.Extension{{
				Id:       test.identifier,
				Critical: true,
				Value:    test.value,
			}}}
			target := certzcrypto.BuildTree(certificate)
			extension := target.Children["extensions"].Children[test.identifier.String()]
			if unprocessed := extension.Children["unprocessed"]; unprocessed == nil || unprocessed.Value != true {
				t.Fatal("extension content was not marked unprocessed")
			}
			got, err := op.Evaluate(target, nil, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got {
				t.Fatal("NoUnknownCriticalExtensions accepted unprocessed critical content")
			}

			certificate.Extensions[0].Critical = false
			target = certzcrypto.BuildTree(certificate)
			got, err = op.Evaluate(target, nil, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got {
				t.Fatal("NoUnknownCriticalExtensions rejected noncritical unprocessed content")
			}
		})
	}
}
