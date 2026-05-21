package evaluator

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
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
	stdocsp "golang.org/x/crypto/ocsp"
	zx509 "github.com/zmap/zcrypto/x509"
)

func TestOCSP_skipsNilResponse(t *testing.T) {
	ctx := Context{
		Registry: operator.DefaultRegistry(),
		OCSPs:    []*ocsp.Info{{Response: nil, FilePath: "empty.ocsp"}},
	}
	if len(OCSP(ctx)) != 0 {
		t.Fatal("nil OCSP response should produce no results")
	}
}

func TestOcspSigningCert_invalidEmbeddedCert(t *testing.T) {
	ctx := Context{Registry: operator.DefaultRegistry()}
	results := ocspSigningCert(ctx, &ocsp.Info{
		Response: &stdocsp.Response{Certificate: &cryptox509.Certificate{}},
		FilePath: "bad.ocsp",
	})
	if len(results) != 0 {
		t.Fatalf("invalid embedded cert should yield no results, got %d", len(results))
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
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	responderKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	issuerTemplate := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cryptopkix.Name{CommonName: "OCSP Issuer CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerDER, err := cryptox509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	issuerStd, err := cryptox509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}

	responderTemplate := &cryptox509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        cryptopkix.Name{CommonName: "OCSP Responder"},
		NotBefore:      issuerTemplate.NotBefore,
		NotAfter:       issuerTemplate.NotAfter,
		KeyUsage:       cryptox509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []cryptox509.ExtKeyUsage{cryptox509.ExtKeyUsageOCSPSigning},
		AuthorityKeyId: []byte{0x01},
	}
	responderDER, err := cryptox509.CreateCertificate(rand.Reader, responderTemplate, issuerStd, &responderKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create responder: %v", err)
	}
	responderStd, err := cryptox509.ParseCertificate(responderDER)
	if err != nil {
		t.Fatalf("parse responder: %v", err)
	}

	ocspDER, err := stdocsp.CreateResponse(issuerStd, responderStd, stdocsp.Response{
		Status:       stdocsp.Good,
		SerialNumber: big.NewInt(100),
		ThisUpdate:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		IssuerHash:   crypto.SHA256,
	}, responderKey)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	resp, err := stdocsp.ParseResponse(ocspDER, nil)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	// golang.org/x/crypto/ocsp may omit Certificate; evaluator still needs it.
	resp.Certificate = responderStd

	issuerZ, err := zx509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse issuer zcrypto: %v", err)
	}

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
