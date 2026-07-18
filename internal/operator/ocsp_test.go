package operator

import (
	"path/filepath"
	"testing"
	"time"

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
	}{
		{name: "absent"},
		{name: "good", responseFile: "good-leaf.ocsp", wantValid: true, wantNotRevoked: true, wantGood: true},
		{name: "good without nextUpdate", responseFile: "no-next-update-leaf.ocsp", wantValid: true, wantNotRevoked: true, wantGood: true},
		{name: "revoked", responseFile: "revoked-leaf.ocsp", wantValid: true},
		{name: "unknown", responseFile: "unknown-leaf.ocsp", wantValid: true},
		{name: "different serial", responseFile: "wrong-leaf.ocsp"},
		{name: "issuer mismatch", responseFile: "issuer-mismatch-leaf.ocsp"},
		{name: "bad signature", responseFile: "wrong-signer-leaf.ocsp"},
		{name: "stale", responseFile: "stale-leaf.ocsp", afterNextUpdate: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := loadOCSPOperatorContext(t, test.responseFile, test.afterNextUpdate)

			valid, err := (OCSPValid{}).Evaluate(nil, ctx, nil)
			if err != nil {
				t.Fatalf("ocspValid: %v", err)
			}
			notRevoked, err := (NotRevokedOCSP{}).Evaluate(nil, ctx, nil)
			if err != nil {
				t.Fatalf("notRevokedOCSP: %v", err)
			}
			good, err := (OCSPGood{}).Evaluate(nil, ctx, nil)
			if err != nil {
				t.Fatalf("ocspGood: %v", err)
			}

			if valid != test.wantValid || notRevoked != test.wantNotRevoked || good != test.wantGood {
				t.Fatalf("results = (valid=%v, notRevoked=%v, good=%v), want (%v, %v, %v)",
					valid, notRevoked, good, test.wantValid, test.wantNotRevoked, test.wantGood)
			}
		})
	}
}

func TestOCSPOperatorsFailClosedWithoutIssuer(t *testing.T) {
	ctx := loadOCSPOperatorContext(t, "good-leaf.ocsp", false)
	ctx.Chain = ctx.Chain[:1]

	for _, operator := range []Operator{OCSPValid{}, NotRevokedOCSP{}, OCSPGood{}} {
		got, err := operator.Evaluate(nil, ctx, nil)
		if err != nil {
			t.Fatalf("%s: %v", operator.Name(), err)
		}
		if got {
			t.Fatalf("%s accepted evidence without its issuer", operator.Name())
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

	responses, err := ocsp.GetOCSPs(filepath.Join("..", "..", "tests", "ocsps", responseFile))
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
	certificates, err := cert.LoadCertificates(path)
	if err != nil {
		t.Fatalf("load certificate %s: %v", path, err)
	}
	if len(certificates) != 1 {
		t.Fatalf("certificate count for %s = %d, want 1", path, len(certificates))
	}
	return certificates[0]
}
