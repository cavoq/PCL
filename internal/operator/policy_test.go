package operator

import (
	"testing"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/cert"
)

func TestCertificatePolicyValidName(t *testing.T) {
	op := CertificatePolicyValid{}
	if op.Name() != "certificatePolicyValid" {
		t.Error("wrong name")
	}
}

func TestCertificatePolicyValidNilContext(t *testing.T) {
	op := CertificatePolicyValid{}
	got, err := op.Evaluate(nil, nil, []any{"1.2.3.4"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil context should return false")
	}
}

func TestCertificatePolicyValidNoOperands(t *testing.T) {
	op := CertificatePolicyValid{}
	ctx := &EvaluationContext{
		Cert:  &cert.Info{Cert: &x509.Certificate{}},
		Chain: []*cert.Info{{Cert: &x509.Certificate{}}},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("no operands should return false")
	}
}

func TestCertificatePolicyValidWithAnyPolicy(t *testing.T) {
	op := CertificatePolicyValid{}
	leafCert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			{2, 5, 29, 32, 0},
		},
	}
	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
		},
	}
	got, err := op.Evaluate(nil, ctx, []any{"1.2.3.4"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("anyPolicy should satisfy any acceptable policy")
	}
}

func TestCertificatePolicyValidExactMatch(t *testing.T) {
	op := CertificatePolicyValid{}
	policyOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	leafCert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{policyOID},
	}
	rootCert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{policyOID},
	}
	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: rootCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, []any{"1.2.3.4"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("exact policy match should pass")
	}
}

func TestCertificatePolicyValidNoMatch(t *testing.T) {
	op := CertificatePolicyValid{}
	leafCert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	rootCert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: rootCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, []any{"5.6.7.8"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("no matching policy should fail")
	}
}

func TestCertificatePolicyValidPolicyIntersection(t *testing.T) {
	op := CertificatePolicyValid{}
	leafCert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	caCert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 5}},
	}
	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, []any{"1.2.3.4"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("policy not present in all certs should fail")
	}
}

func TestCertificatePolicyValidNoPoliciesInCert(t *testing.T) {
	op := CertificatePolicyValid{}
	leafCert := &x509.Certificate{
		PolicyIdentifiers: nil,
	}
	rootCert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: rootCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, []any{"1.2.3.4"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("cert without policies should fail")
	}
}

func TestCertificatePolicyValidMultipleAcceptable(t *testing.T) {
	op := CertificatePolicyValid{}
	leafCert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{{5, 6, 7, 8}},
	}
	rootCert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{{5, 6, 7, 8}},
	}
	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: rootCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, []any{"1.2.3.4", "5.6.7.8"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("one of multiple acceptable policies should pass")
	}
}
