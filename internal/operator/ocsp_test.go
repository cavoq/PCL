package operator

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/ocsp"
)

func TestOCSPOperatorNames(t *testing.T) {
	tests := []struct {
		operator Operator
		want     string
	}{
		{operator: OCSPValid{}, want: "ocspValid"},
		{operator: NotRevokedOCSP{}, want: "notRevokedOCSP"},
		{operator: OCSPGood{}, want: "ocspGood"},
	}
	for _, test := range tests {
		if got := test.operator.Name(); got != test.want {
			t.Errorf("name = %q, want %q", got, test.want)
		}
	}
}

func TestOCSPOperatorsUseAcceptedEvidence(t *testing.T) {
	tests := []struct {
		name            string
		responseFile    string
		afterNextUpdate bool
		wantValid       bool
		wantNotRevoked  bool
		wantGood        bool
		// wantNoEvidence: no response applies to the certificate, so every
		// operator is undecided rather than false.
		wantNoEvidence bool
	}{
		{name: "absent", wantNoEvidence: true},
		{name: "good", responseFile: "good-leaf.ocsp", wantValid: true, wantNotRevoked: true, wantGood: true},
		{name: "good without nextUpdate", responseFile: "no-next-update-leaf.ocsp", wantValid: true, wantNotRevoked: true, wantGood: true},
		{name: "revoked", responseFile: "revoked-leaf.ocsp", wantValid: true},
		{name: "unknown", responseFile: "unknown-leaf.ocsp", wantValid: true},
		{name: "different serial", responseFile: "wrong-leaf.ocsp", wantNoEvidence: true},
		// The context's chain lacks the root the response names as issuer.
		{name: "issuer mismatch", responseFile: "issuer-mismatch-leaf.ocsp", wantNoEvidence: true},
		{name: "bad signature", responseFile: "wrong-signer-leaf.ocsp"},
		{name: "stale", responseFile: "stale-leaf.ocsp", afterNextUpdate: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := loadOCSPOperatorContext(t, test.responseFile, test.afterNextUpdate)
			if test.wantNoEvidence {
				assertOCSPOperatorsLackEvidence(t, ctx)
				return
			}
			assertOCSPOperatorResults(t, ctx, test.wantValid, test.wantNotRevoked, test.wantGood)
		})
	}
}

// Without the issuer a response cannot be bound to the certificate, so it is
// no evidence for it: the operators stay undecided and never accept it.
func TestOCSPOperatorsDoNotAcceptEvidenceWithoutIssuer(t *testing.T) {
	ctx := loadOCSPOperatorContext(t, "good-leaf.ocsp", false)
	ctx.Chain = ctx.Chain[:1]

	assertOCSPOperatorsLackEvidence(t, ctx)
}

func TestOCSPOperatorsUseCachedAssessment(t *testing.T) {
	acceptedGood := acceptedOCSPAssessment(ocsp.StatusGood)
	acceptedRevoked := acceptedOCSPAssessment(ocsp.StatusRevoked)

	t.Run("cached good without raw evidence", func(t *testing.T) {
		ctx := &EvaluationContext{
			Cert:           &cert.Info{Cert: &x509.Certificate{}},
			OCSPAssessment: &acceptedGood,
		}
		assertOCSPOperatorResults(t, ctx, true, true, true)
	})

	t.Run("cached revoked overrides raw good evidence", func(t *testing.T) {
		ctx := loadOCSPOperatorContext(t, "good-leaf.ocsp", false)
		ctx.OCSPAssessment = &acceptedRevoked
		assertOCSPOperatorResults(t, ctx, true, false, false)
	})
}

func TestOCSPOperatorsTreatEmptyCachedAssessmentAsAuthoritative(t *testing.T) {
	ctx := loadOCSPOperatorContext(t, "good-leaf.ocsp", false)
	ctx.OCSPAssessment = &ocsp.Assessment{}

	assertOCSPOperatorsLackEvidence(t, ctx)
}

func TestOCSPOperatorsFailClosedWithoutTargetDespiteCachedAssessment(t *testing.T) {
	acceptedGood := acceptedOCSPAssessment(ocsp.StatusGood)
	ctx := &EvaluationContext{OCSPAssessment: &acceptedGood}

	assertOCSPOperatorResults(t, ctx, false, false, false)
}

func TestOCSPOperatorsFallBackToRawEvidenceWithoutCachedAssessment(t *testing.T) {
	ctx := loadOCSPOperatorContext(t, "good-leaf.ocsp", false)
	if ctx.OCSPAssessment != nil {
		t.Fatal("fixture unexpectedly supplied a cached assessment")
	}

	assertOCSPOperatorResults(t, ctx, true, true, true)
}

func acceptedOCSPAssessment(status ocsp.Status) ocsp.Assessment {
	return ocsp.Assessment{Evidence: []ocsp.Evidence{{
		Status:         status,
		Applicable:     true,
		Current:        true,
		IssuerMatched:  true,
		SignatureValid: true,
	}}}
}

func assertOCSPOperatorResults(t *testing.T, ctx *EvaluationContext, wantValid, wantNotRevoked, wantGood bool) {
	t.Helper()

	tests := []struct {
		operator Operator
		want     bool
	}{
		{operator: OCSPValid{}, want: wantValid},
		{operator: NotRevokedOCSP{}, want: wantNotRevoked},
		{operator: OCSPGood{}, want: wantGood},
	}
	for _, test := range tests {
		got, err := test.operator.Evaluate(nil, ctx, nil)
		if err != nil {
			t.Fatalf("%s: %v", test.operator.Name(), err)
		}
		if got != test.want {
			t.Errorf("%s = %v, want %v", test.operator.Name(), got, test.want)
		}
	}
}

// assertOCSPOperatorsLackEvidence checks that every OCSP operator reports a
// NoEvidenceError and accepts nothing.
func assertOCSPOperatorsLackEvidence(t *testing.T, ctx *EvaluationContext) {
	t.Helper()
	for _, operator := range []Operator{OCSPValid{}, NotRevokedOCSP{}, OCSPGood{}} {
		got, err := operator.Evaluate(nil, ctx, nil)
		var noEvidence NoEvidenceError
		if got || !errors.As(err, &noEvidence) {
			t.Errorf("%s = %v, %v; want false with NoEvidenceError", operator.Name(), got, err)
		}
	}
}

func loadOCSPOperatorContext(t *testing.T, responseFile string, afterNextUpdate bool) *EvaluationContext {
	t.Helper()

	leaf := loadSingleCertificate(t, filepath.Join("..", "..", "tests", "certs", "ocsp-leaf.pem"))
	issuer := loadSingleCertificate(t, filepath.Join("..", "..", "tests", "certs", "ocsp-intermediate.pem"))
	ctx := &EvaluationContext{
		Cert:  leaf,
		Chain: []*cert.Info{leaf, issuer},
	}
	if responseFile == "" {
		ctx.Now = time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
		return ctx
	}

	responses, err := ocsp.GetOCSPs(filepath.Join("..", "..", "tests", "ocsps", responseFile), nil)
	if err != nil {
		t.Fatalf("load OCSP response %s: %v", responseFile, err)
	}
	if len(responses) != 1 || responses[0] == nil || responses[0].Response == nil {
		t.Fatalf("expected one OCSP response from %s", responseFile)
	}
	ctx.OCSPs = responses
	ctx.Now = responses[0].Response.ThisUpdate
	if afterNextUpdate {
		if responses[0].Response.NextUpdate.IsZero() {
			t.Fatalf("fixture %s has no nextUpdate", responseFile)
		}
		ctx.Now = responses[0].Response.NextUpdate.Add(time.Second)
	}
	return ctx
}

func loadSingleCertificate(t *testing.T, path string) *cert.Info {
	t.Helper()
	certificates, err := cert.LoadCertificates(path, nil)
	if err != nil {
		t.Fatalf("load certificate %s: %v", path, err)
	}
	if len(certificates) != 1 {
		t.Fatalf("certificate count for %s = %d, want 1", path, len(certificates))
	}
	return certificates[0]
}
