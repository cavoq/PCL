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
		Chain:    []*cert.Info{{Cert: issuerZ, FilePath: "issuer.pem", Type: "root"}},
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
