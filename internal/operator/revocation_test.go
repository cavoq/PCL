package operator

import (
	"errors"
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

	staleCRL := crl.Assessment{Evidence: []crl.Evidence{{Applicable: true, Rejection: crl.EvidenceNotCurrent}}}
	unrelatedCRL := crl.Assessment{Evidence: []crl.Evidence{{Rejection: crl.EvidenceUnrelated}}}

	tests := []struct {
		name           string
		crl            *crl.Assessment
		ocsp           *ocsp.Assessment
		want           bool
		wantNoEvidence bool
	}{
		{name: "no evidence", wantNoEvidence: true},
		{name: "only an unrelated CRL", crl: &unrelatedCRL, wantNoEvidence: true},
		{name: "applicable CRL that is not current", crl: &staleCRL, want: false},
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
			var noEvidence NoEvidenceError
			if errors.As(err, &noEvidence) != test.wantNoEvidence {
				t.Fatalf("Evaluate error = %v, want NoEvidenceError: %v", err, test.wantNoEvidence)
			}
			if err != nil && !test.wantNoEvidence {
				t.Fatalf("Evaluate: %v", err)
			}
			if got != test.want {
				t.Fatalf("Evaluate = %v, want %v", got, test.want)
			}
		})
	}
}
