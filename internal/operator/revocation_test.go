package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/zmap/zcrypto/x509"
)

func TestNotRevokedByAvailableEvidence(t *testing.T) {
	goodCRL := crl.Assessment{CoveredReasons: crl.AllReasons}
	revokedCRL := crl.Assessment{Revocation: &crl.Revocation{}}
	goodOCSP := ocsp.Assessment{Evidence: []ocsp.Evidence{{
		Applicable: true, Current: true, IssuerMatched: true, SignatureValid: true,
		Status: ocsp.StatusGood,
	}}}
	revokedOCSP := ocsp.Assessment{Evidence: []ocsp.Evidence{{
		Applicable: true, Current: true, IssuerMatched: true, SignatureValid: true,
		Status: ocsp.StatusRevoked,
	}}}

	tests := []struct {
		name string
		crl  *crl.Assessment
		ocsp *ocsp.Assessment
		want bool
	}{
		{name: "no evidence", want: false},
		{name: "good CRL", crl: &goodCRL, want: true},
		{name: "good OCSP", ocsp: &goodOCSP, want: true},
		{name: "revoked CRL overrides good OCSP", crl: &revokedCRL, ocsp: &goodOCSP, want: false},
		{name: "revoked OCSP overrides good CRL", crl: &goodCRL, ocsp: &revokedOCSP, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := NewEvaluationContext(nil, &cert.Info{Cert: &x509.Certificate{}}, nil)
			ctx.CRLAssessment = test.crl
			ctx.OCSPAssessment = test.ocsp

			got, err := (NotRevokedByAvailableEvidence{}).Evaluate(nil, ctx, nil)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got != test.want {
				t.Fatalf("Evaluate = %v, want %v", got, test.want)
			}
		})
	}
}
