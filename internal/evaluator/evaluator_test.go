package evaluator

import (
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestChainWithEmptyChain(t *testing.T) {
	evalCtx := Context{
		Policies: nil,
		Registry: operator.DefaultRegistry(),
		CRLs:     nil,
		OCSPs:    nil,
		Chain:    []*cert.Info{},
	}

	results := Chain(evalCtx)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty chain, got %d", len(results))
	}
}

func TestCRLOnlyWithEmptyCRLs(t *testing.T) {
	results := CRLOnly(nil, operator.DefaultRegistry(), nil, nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty CRLs, got %d", len(results))
	}
}

func TestOCSPOnlyWithEmptyOCSPs(t *testing.T) {
	results := OCSPOnly(nil, operator.DefaultRegistry(), nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty OCSPs, got %d", len(results))
	}
}

func TestExtractCertsFromInfoEmpty(t *testing.T) {
	certs := ExtractCertsFromInfo(nil)
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for nil input, got %d", len(certs))
	}

	certs = ExtractCertsFromInfo([]*cert.Info{})
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for empty slice, got %d", len(certs))
	}
}

func TestExtractCertsFromInfoWithNilCert(t *testing.T) {
	infos := []*cert.Info{
		{Cert: nil},
		{Cert: nil, FilePath: "test.pem"},
	}
	certs := ExtractCertsFromInfo(infos)
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for nil certs in info, got %d", len(certs))
	}
}

func TestContextDefaults(t *testing.T) {
	evalCtx := Context{}

	if evalCtx.Registry == nil {
		t.Log("Registry is nil in default context (expected)")
	}
	if evalCtx.Chain != nil {
		t.Errorf("expected nil Chain in default context")
	}
	if evalCtx.CRLs != nil {
		t.Errorf("expected nil CRLs in default context")
	}
	if evalCtx.OCSPs != nil {
		t.Errorf("expected nil OCSPs in default context")
	}
}

func TestIssuerCertsForCRL_withResolveEnabled(t *testing.T) {
	signer := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "CA"},
		SubjectKeyId: []byte{0x01},
		IsCA:         true,
		SerialNumber: big.NewInt(1),
	}
	revocationList := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "CA"},
		AuthorityKeyId: []byte{0x01},
	}
	chain := []*cert.Info{{Cert: signer}}

	ctx := Context{
		Chain:              chain,
		CRLResolveTimeout:  time.Second,
		CRLResolveMaxDepth: 1,
	}
	pool := issuerCertsForCRL(ctx, revocationList)
	if len(pool) != 1 || pool[0] != signer {
		t.Fatalf("issuerCertsForCRL() = %v, want chain signer", pool)
	}
}

func TestIssuerCertsForCRL_withoutResolve(t *testing.T) {
	signer := &x509.Certificate{SerialNumber: big.NewInt(1)}
	chain := []*cert.Info{{Cert: signer}}
	ctx := Context{Chain: chain}

	pool := issuerCertsForCRL(ctx, &x509.RevocationList{})
	if len(pool) != 1 || pool[0] != signer {
		t.Fatalf("issuerCertsForCRL() = %v", pool)
	}
}

func TestCRL_setsIsCACRLNode(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "CRL CA"},
		SubjectKeyId: []byte{0x0c},
		IsCA:         true,
		SerialNumber: big.NewInt(1),
	}
	revocationList := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "CRL CA"},
		AuthorityKeyId: []byte{0x0c},
		ThisUpdate:     now,
		NextUpdate:     now.Add(7 * 24 * time.Hour),
	}

	ctx := Context{
		Policies: nil,
		Registry: operator.DefaultRegistry(),
		CRLs: []*crl.Info{{
			CRL:      revocationList,
			FilePath: "test.crl",
		}},
		Chain: []*cert.Info{{Cert: signer}},
	}

	results := CRL(ctx)
	if len(results) != 0 {
		t.Fatalf("expected 0 policy results with nil policies, got %d", len(results))
	}

	pool := issuerCertsForCRL(ctx, revocationList)
	tree := crl.BuildTreeWithChain(revocationList, pool)
	if tree.Children["isCACRL"].Value != true {
		t.Fatalf("isCACRL = %v, want true", tree.Children["isCACRL"].Value)
	}
}

func TestIssuerCertsForCRL_withoutResolveFlags(t *testing.T) {
	chain := []*cert.Info{{Cert: &x509.Certificate{SerialNumber: big.NewInt(1)}}}
	ctx := Context{Chain: chain, CRLResolveTimeout: 0}
	pool := issuerCertsForCRL(ctx, &x509.RevocationList{})
	if len(pool) != 1 {
		t.Fatalf("issuerCertsForCRL() = %v, want chain only", pool)
	}
}

func TestPrepareCRLIssuersSharesPoolWithCertificatePass(t *testing.T) {
	signer := &x509.Certificate{SerialNumber: big.NewInt(1)}
	crlInfo := &crl.Info{CRL: &x509.RevocationList{}}
	ctx := PrepareCRLIssuers(Context{
		Chain: []*cert.Info{{Cert: signer}},
		CRLs:  []*crl.Info{crlInfo},
	})

	perCRL := ctx.crlIssuerPools[crlInfo]
	combined := combinedCRLIssuerPool(ctx)
	if len(perCRL) != 1 || perCRL[0] != signer {
		t.Fatalf("per-CRL issuer pool = %v, want signer", perCRL)
	}
	if len(combined) != 1 || combined[0] != signer {
		t.Fatalf("certificate-pass issuer pool = %v, want same signer", combined)
	}
}

func TestCRL_skipsNilEntries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "CRL CA"},
		AuthorityKeyId: []byte{0x0d},
		ThisUpdate:     now,
		NextUpdate:     now.Add(time.Hour),
	}
	signer := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "CRL CA"},
		SubjectKeyId: []byte{0x0d},
		IsCA:         true,
		SerialNumber: big.NewInt(1),
	}

	pol, err := policy.ParseFile(filepath.Join("..", "..", "tests", "policies", "crl-validity.yaml"))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	ctx := Context{
		Policies:           []policy.Policy{pol},
		Registry:           operator.DefaultRegistry(),
		CRLs:               []*crl.Info{nil, {CRL: nil}, {CRL: valid, FilePath: "test.crl"}},
		Chain:              []*cert.Info{{Cert: signer}},
		CRLResolveTimeout:  time.Second,
		CRLResolveMaxDepth: 1,
	}
	results := CRL(ctx)
	if len(results) == 0 {
		t.Fatal("expected CRL policy results for valid CRL entry")
	}
}

type currentCRLProbe struct{}

func (currentCRLProbe) Name() string { return "currentCRLProbe" }

func (currentCRLProbe) Evaluate(_ *node.Node, ctx *operator.EvaluationContext, _ []any) (bool, error) {
	profile := ctx.ProfileCRLs()
	return ctx.CurrentCRL != nil && len(profile) == 1 && profile[0] == ctx.CurrentCRL, nil
}

func TestCRL_bindsEachCurrentCRL(t *testing.T) {
	registry := operator.NewRegistry()
	registry.Register(currentCRLProbe{})
	pol := policy.Policy{
		ID: "current-crl",
		Rules: []rule.Rule{{
			ID:       "current-crl",
			Target:   "crl",
			Operator: "currentCRLProbe",
			Severity: "error",
		}},
	}
	lists := []*crl.Info{
		{CRL: &x509.RevocationList{Issuer: pkix.Name{CommonName: "One"}}},
		{CRL: &x509.RevocationList{Issuer: pkix.Name{CommonName: "Two"}}},
	}

	results := CRL(Context{Policies: []policy.Policy{pol}, Registry: registry, CRLs: lists})
	if len(results) != 2 {
		t.Fatalf("results = %d, want one per CRL", len(results))
	}
	for i, result := range results {
		if result.Verdict != rule.VerdictPass {
			t.Fatalf("result %d verdict = %s, want pass", i, result.Verdict)
		}
	}
}

func TestCRL_resolvesIssuerViaAIA(t *testing.T) {
	parentDER, parent := testEvaluatorCRLCA(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(parentDER)
	}))
	defer server.Close()

	leaf := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "subscriber"},
		Issuer:                parent.Subject,
		SerialNumber:          big.NewInt(2),
		IssuingCertificateURL: []string{server.URL},
	}
	revocationList := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "Different DN"},
		AuthorityKeyId: []byte{0x01, 0x02},
		ThisUpdate:     time.Now().UTC().Add(-time.Hour),
		NextUpdate:     time.Now().UTC().Add(time.Hour),
	}

	ctx := Context{
		Registry:           operator.DefaultRegistry(),
		CRLs:               []*crl.Info{{CRL: revocationList, FilePath: "fetched.crl", Source: source.Info{Type: source.Local}}},
		Chain:              []*cert.Info{{Cert: leaf}},
		CRLResolveTimeout:  time.Second,
		CRLResolveMaxDepth: 2,
	}
	pool := issuerCertsForCRL(ctx, revocationList)
	if len(pool) < 2 {
		t.Fatalf("issuerCertsForCRL() len = %d, want fetched signer", len(pool))
	}
}

func testEvaluatorCRLCA(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cryptopkix.Name{CommonName: "CRL CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01, 0x02},
	}
	der, err := cryptox509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return der, parsed
}
