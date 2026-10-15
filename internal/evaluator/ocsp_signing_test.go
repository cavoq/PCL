package evaluator

import (
	"crypto"
	cryptox509 "crypto/x509"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
	"github.com/cavoq/PCL/internal/testpki"
	stdocsp "golang.org/x/crypto/ocsp"
)

func TestOCSP_skipsNilInfoAndResponse(t *testing.T) {
	ctx := Context{
		Registry: operator.DefaultRegistry(),
		OCSPs:    []*ocsp.Info{nil, {Response: nil, FilePath: "empty.ocsp"}},
	}
	if len(OCSP(ctx)) != 0 {
		t.Fatal("nil OCSP info and response should produce no results")
	}
}

func TestOcspSigningCert_invalidEmbeddedCert(t *testing.T) {
	ctx := Context{Registry: operator.DefaultRegistry()}
	_, ok := ocspSignerSubject(ctx, &ocsp.Info{
		Response: &stdocsp.Response{Certificate: &cryptox509.Certificate{}},
		FilePath: "bad.ocsp",
	}, time.Now())
	if ok {
		t.Fatal("invalid embedded cert should yield no signer subject")
	}
}

func TestOCSP_runsOcspTargetPolicy(t *testing.T) {
	resp := &stdocsp.Response{
		Status:     stdocsp.Good,
		ThisUpdate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	ctx := Context{
		Policies: []policy.Policy{{
			ID: "ocsp-only",
			Rules: []rule.Rule{{
				ID:       "ocsp-status-good",
				Target:   "ocsp.status",
				Operator: "eq",
				Operands: []any{"Good"},
				Severity: "error",
			}},
		}},
		Registry: operator.DefaultRegistry(),
		OCSPs:    []*ocsp.Info{{Response: resp, FilePath: "inline.ocsp"}},
	}
	results := OCSP(ctx)
	if len(results) == 0 {
		t.Fatal("expected OCSP-target policy results")
	}
}

func TestOCSP_evaluatesEmbeddedSigningCert(t *testing.T) {
	issuer := testpki.Issue(t, "OCSP Issuer CA", nil, testpki.CA())
	responder := testpki.Issue(t, "OCSP Responder", issuer, testpki.Serial(2), testpki.OCSPSigning())
	resp := testpki.OCSPResponse(t, issuer, responder, stdocsp.Response{
		Status:       stdocsp.Good,
		SerialNumber: big.NewInt(100),
		ThisUpdate:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		IssuerHash:   crypto.SHA256,
	})
	// golang.org/x/crypto/ocsp may omit Certificate; evaluator still needs it.
	resp.Certificate = responder.Std
	issuerZ := issuer.Cert

	pol, err := policy.ParseFile(filepath.Join("..", "..", "tests", "policies", "basic.yaml"))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	ctx := Context{
		Policies: []policy.Policy{pol},
		Registry: operator.DefaultRegistry(),
		OCSPs:    []*ocsp.Info{{Response: resp, FilePath: "test.ocsp"}},
		Chain:    []*cert.Info{{Cert: issuerZ, FilePath: "issuer.pem"}},
	}

	results := OCSP(ctx)
	if len(results) == 0 {
		t.Fatal("expected OCSP policy results")
	}

	var sawSigning bool
	for _, r := range results {
		if r.CertType == "ocspSigning" || strings.Contains(r.CertPath, "signing cert") {
			sawSigning = true
			break
		}
	}
	if !sawSigning {
		t.Fatalf("expected policy results for embedded OCSP signing cert, got %d results", len(results))
	}
}

// A delegated responder issued by an upper intermediate shares that part of
// the certificate chain. Building its signer chain must not move the shared
// certificates, or chain operators would look up the wrong issuer.
func TestOCSPSubjects_keepChainSubjectPositions(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA())
	upper := testpki.Issue(t, "Upper Intermediate", root, testpki.CA(), testpki.Serial(2))
	lower := testpki.Issue(t, "Lower Intermediate", upper, testpki.CA(), testpki.Serial(3))
	leaf := testpki.Issue(t, "Leaf", lower, testpki.Serial(4))
	responder := testpki.Issue(t, "OCSP Responder", upper, testpki.Serial(5), testpki.OCSPSigning())
	resp := testpki.OCSPResponse(t, upper, responder, stdocsp.Response{
		Status:       stdocsp.Good,
		SerialNumber: big.NewInt(3),
		ThisUpdate:   testpki.NotBefore,
		NextUpdate:   testpki.NotAfter,
		Certificate:  responder.Std,
	})

	chain := []*cert.Info{{Cert: leaf.Cert}, {Cert: lower.Cert}, {Cert: upper.Cert}, {Cert: root.Cert}}
	ctx := Context{
		Registry:       operator.DefaultRegistry(),
		Chain:          chain,
		OCSPs:          []*ocsp.Info{{Response: resp, FilePath: "responder.ocsp"}},
		ValidationTime: testpki.NotBefore.AddDate(0, 1, 0),
	}

	subjects := ChainSubjects(ctx)
	if signers := OCSPSubjects(ctx); len(signers) != 2 {
		t.Fatalf("OCSP subjects = %d, want the response and its signer", len(signers))
	}
	for i, subject := range subjects {
		valid, err := operator.SignatureValid{}.Evaluate(nil, subject.Context, nil)
		if err != nil || !valid {
			t.Errorf("chain certificate %d: signatureValid = %v, %v after building OCSP subjects", i, valid, err)
		}
	}
}
