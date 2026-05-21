package evaluator

import (
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/operator"
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
