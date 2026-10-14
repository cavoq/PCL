package evaluator

import (
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/testpki"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	stdocsp "golang.org/x/crypto/ocsp"
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
	results := CRL(Context{Registry: operator.DefaultRegistry()})
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty CRLs, got %d", len(results))
	}
}

func TestOCSPOnlyWithEmptyOCSPs(t *testing.T) {
	results := OCSP(Context{Registry: operator.DefaultRegistry()})
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty OCSPs, got %d", len(results))
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

func TestChainProjectsAndPropagatesApplicationPurpose(t *testing.T) {
	certificate := &cert.Info{
		Cert:     &x509.Certificate{},
		Type:     "leaf",
		Position: 0,
	}
	profile := policy.Policy{
		ID: "application-purpose",
		Rules: []rule.Rule{
			{
				ID:       "purpose-node",
				Target:   "certificate.applicationPurpose",
				Operator: "eq",
				Operands: []any{"serverAuth"},
				Severity: rule.SeverityError,
			},
			{
				ID:       "purpose-semantics",
				Target:   "certificate",
				Operator: "applicationPurposeValid",
				Severity: rule.SeverityError,
			},
		},
	}

	results := Chain(Context{
		Policies:           []policy.Policy{profile},
		Registry:           operator.DefaultRegistry(),
		Chain:              []*cert.Info{certificate},
		ApplicationPurpose: "serverAuth",
	})
	if len(results) != 1 || len(results[0].Results) != 2 {
		t.Fatalf("results = %#v, want one policy result with two rules", results)
	}
	for _, result := range results[0].Results {
		if result.Verdict != rule.VerdictPass {
			t.Fatalf("rule %q verdict = %q, want pass", result.RuleID, result.Verdict)
		}
	}
}

func TestProjectApplicationPurposeOmitsAbsentInput(t *testing.T) {
	tree := node.New("certificate", nil)
	projectApplicationPurpose(tree, "")
	if _, present := tree.Children["applicationPurpose"]; present {
		t.Fatal("absent application purpose was projected")
	}
}

func TestChainProjectsExplicitUnknownRevocationWithoutAttachingACRL(t *testing.T) {
	certificate := &cert.Info{
		Cert:     &x509.Certificate{SerialNumber: big.NewInt(42)},
		Type:     "leaf",
		Position: 0,
	}
	profile := policy.Policy{
		ID: "revocation-projection",
		Rules: []rule.Rule{
			{
				ID:       "status",
				Target:   "certificate.revocation.status",
				Operator: "eq",
				Operands: []any{"unknown"},
				Severity: rule.SeverityError,
			},
			{
				ID:       "covered-reasons",
				Target:   "certificate.revocation.coveredReasons",
				Operator: "eq",
				Operands: []any{0},
				Severity: rule.SeverityError,
			},
			{
				ID:       "no-arbitrary-crl",
				Target:   "certificate.crl",
				Operator: "absent",
				Severity: rule.SeverityError,
			},
		},
	}

	results := Chain(Context{
		Policies:            []policy.Policy{profile},
		Registry:            operator.DefaultRegistry(),
		Chain:               []*cert.Info{certificate},
		CRLs:                []*crl.Info{{CRL: &x509.RevocationList{}}},
		RevocationRequested: true,
		ValidationTime:      time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC),
	})
	if len(results) != 1 || len(results[0].Results) != 3 {
		t.Fatalf("results = %#v, want one policy result with three rules", results)
	}
	for _, result := range results[0].Results {
		if result.Verdict != rule.VerdictPass {
			t.Fatalf("rule %q verdict = %q, want pass", result.RuleID, result.Verdict)
		}
	}
}

func TestChainOmitsRevocationWhenItWasNotRequested(t *testing.T) {
	profile := policy.Policy{
		ID: "revocation-absent",
		Rules: []rule.Rule{{
			ID:       "revocation-absent",
			Target:   "certificate.revocation",
			Operator: "absent",
			Severity: rule.SeverityError,
		}},
	}
	results := Chain(Context{
		Policies: []policy.Policy{profile},
		Registry: operator.DefaultRegistry(),
		Chain: []*cert.Info{{
			Cert: &x509.Certificate{SerialNumber: big.NewInt(42)}, Type: "leaf",
		}},
		ValidationTime: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC),
	})
	if len(results) != 1 || results[0].Verdict != rule.VerdictPass {
		t.Fatalf("results = %#v, want absent revocation to pass", results)
	}
}

type evaluationTimeProbe struct{ expected time.Time }

func (probe evaluationTimeProbe) Name() string { return "evaluationTimeProbe" }

func (probe evaluationTimeProbe) Evaluate(
	_ *node.Node,
	ctx *operator.EvaluationContext,
	_ []any,
) (bool, error) {
	return ctx != nil && ctx.Now.Equal(probe.expected), nil
}

func TestChainUsesConfiguredValidationTime(t *testing.T) {
	expected := time.Date(2026, 8, 14, 12, 0, 0, 123, time.UTC)
	registry := operator.NewRegistry()
	registry.Register(evaluationTimeProbe{expected: expected})
	profile := policy.Policy{
		ID: "validation-time",
		Rules: []rule.Rule{{
			ID:       "validation-time",
			Target:   "certificate",
			Operator: "evaluationTimeProbe",
			Severity: rule.SeverityError,
		}},
	}
	results := Chain(Context{
		Policies:       []policy.Policy{profile},
		Registry:       registry,
		Chain:          []*cert.Info{{Cert: &x509.Certificate{}, Type: "leaf"}},
		ValidationTime: expected,
	})
	if len(results) != 1 || results[0].Verdict != rule.VerdictPass {
		t.Fatalf("results = %#v, want configured time to reach operators", results)
	}
}

func TestOCSPUsesConfiguredValidationTime(t *testing.T) {
	expected := time.Date(2026, 8, 14, 12, 0, 0, 123, time.UTC)
	registry := operator.NewRegistry()
	registry.Register(evaluationTimeProbe{expected: expected})
	profile := policy.Policy{
		ID: "ocsp-validation-time",
		Rules: []rule.Rule{{
			ID:       "ocsp-validation-time",
			Target:   "ocsp",
			Operator: "evaluationTimeProbe",
			Severity: rule.SeverityError,
		}},
	}
	results := OCSP(Context{
		Policies:       []policy.Policy{profile},
		Registry:       registry,
		OCSPs:          []*ocsp.Info{{Response: &stdocsp.Response{Status: stdocsp.Good}}},
		ValidationTime: expected,
	})
	if len(results) != 1 || results[0].Verdict != rule.VerdictPass {
		t.Fatalf("results = %#v, want configured time to reach OCSP operators", results)
	}
}

type ocspAssessmentProbeState struct {
	applicableSerial string
	unrelatedSerial  string
	evidence         *ocsp.Info
	bySerial         map[string]*ocsp.Assessment
}

type ocspAssessmentProbe struct {
	state *ocspAssessmentProbeState
}

func (ocspAssessmentProbe) Name() string { return "ocspAssessmentProbe" }

func (probe ocspAssessmentProbe) Evaluate(
	_ *node.Node,
	ctx *operator.EvaluationContext,
	_ []any,
) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil ||
		ctx.Cert.Cert.SerialNumber == nil || ctx.OCSPAssessment == nil {
		return false, nil
	}

	serial := ctx.Cert.Cert.SerialNumber.String()
	probe.state.bySerial[serial] = ctx.OCSPAssessment
	if len(ctx.OCSPAssessment.Evidence) != 1 ||
		ctx.OCSPAssessment.Evidence[0].Info != probe.state.evidence {
		return false, nil
	}

	evidence := ctx.OCSPAssessment.Evidence[0]
	switch serial {
	case probe.state.applicableSerial:
		return evidence.Applicable && evidence.Valid() &&
			ctx.OCSPAssessment.Status() == ocsp.StatusGood, nil
	case probe.state.unrelatedSerial:
		return !evidence.Applicable &&
			ctx.OCSPAssessment.Status() == ocsp.StatusNotApplicable, nil
	default:
		return false, nil
	}
}

func TestChainSuppliesTargetScopedOCSPAssessments(t *testing.T) {
	leafCertificates, err := cert.LoadCertificates(
		filepath.Join("..", "..", "tests", "certs", "ocsp-leaf.pem"),
	)
	if err != nil || len(leafCertificates) != 1 {
		t.Fatalf("load OCSP leaf: certificates=%d err=%v", len(leafCertificates), err)
	}
	issuerCertificates, err := cert.LoadCertificates(
		filepath.Join("..", "..", "tests", "certs", "ocsp-intermediate.pem"),
	)
	if err != nil || len(issuerCertificates) != 1 {
		t.Fatalf("load OCSP issuer: certificates=%d err=%v", len(issuerCertificates), err)
	}
	responses, err := ocsp.GetOCSPs(
		filepath.Join("..", "..", "tests", "ocsps", "good-leaf.ocsp"),
	)
	if err != nil || len(responses) != 1 || responses[0] == nil || responses[0].Response == nil {
		t.Fatalf("load OCSP response: responses=%d err=%v", len(responses), err)
	}

	applicable := leafCertificates[0]
	applicable.Type = "leaf"
	unrelatedCertificate := *applicable.Cert
	unrelatedCertificate.SerialNumber = new(big.Int).Add(applicable.Cert.SerialNumber, big.NewInt(1))
	unrelated := &cert.Info{Cert: &unrelatedCertificate, Type: "leaf"}
	issuerCertificates[0].Type = "intermediate"

	state := &ocspAssessmentProbeState{
		applicableSerial: applicable.Cert.SerialNumber.String(),
		unrelatedSerial:  unrelated.Cert.SerialNumber.String(),
		evidence:         responses[0],
		bySerial:         make(map[string]*ocsp.Assessment, 2),
	}
	registry := operator.NewRegistry()
	registry.Register(ocspAssessmentProbe{state: state})
	profile := policy.Policy{
		ID:       "prepared-ocsp-assessment",
		CertType: []string{"leaf"},
		Rules: []rule.Rule{{
			ID:       "prepared-ocsp-assessment",
			Target:   "certificate",
			Operator: "ocspAssessmentProbe",
			Severity: rule.SeverityError,
		}},
	}

	results := Chain(Context{
		Policies:       []policy.Policy{profile},
		Registry:       registry,
		OCSPs:          responses,
		Chain:          []*cert.Info{applicable, unrelated, issuerCertificates[0]},
		ValidationTime: responses[0].Response.ThisUpdate,
	})
	if len(results) != 2 {
		t.Fatalf("results = %#v, want one result for each target leaf", results)
	}
	for _, result := range results {
		if result.Verdict != rule.VerdictPass {
			t.Fatalf("result = %#v, want prepared target-specific assessment to pass", result)
		}
	}

	applicableAssessment := state.bySerial[state.applicableSerial]
	unrelatedAssessment := state.bySerial[state.unrelatedSerial]
	if applicableAssessment == nil || unrelatedAssessment == nil {
		t.Fatalf("observed assessments = %#v, want both target serials", state.bySerial)
	}
	if applicableAssessment == unrelatedAssessment {
		t.Fatal("Chain reused one OCSP assessment across distinct certificate targets")
	}
}

func TestCRLUsesConfiguredValidationTime(t *testing.T) {
	expected := time.Date(2026, 8, 14, 12, 0, 0, 123, time.UTC)
	registry := operator.NewRegistry()
	registry.Register(evaluationTimeProbe{expected: expected})
	profile := policy.Policy{
		ID: "crl-validation-time",
		Rules: []rule.Rule{{
			ID:       "crl-validation-time",
			Target:   "crl",
			Operator: "evaluationTimeProbe",
			Severity: rule.SeverityError,
		}},
	}
	results := CRL(Context{
		Policies: []policy.Policy{profile},
		Registry: registry,
		CRLs: []*crl.Info{{CRL: &x509.RevocationList{
			Issuer: pkix.Name{CommonName: "CRL CA"},
		}}},
		ValidationTime: expected,
	})
	if len(results) != 1 || results[0].Verdict != rule.VerdictPass {
		t.Fatalf("results = %#v, want configured time to reach CRL operators", results)
	}
}

func TestProjectRevocationAssessmentProjectsGoodAndRevokedFacts(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		assessment crl.Assessment
		status     string
		reason     any
	}{
		{
			name: "good",
			assessment: crl.Assessment{
				CoveredReasons: crl.AllReasons,
			},
			status: "good",
		},
		{
			name: "revoked",
			assessment: crl.Assessment{
				Revocation: &crl.Revocation{ReasonCode: 6, RevocationTime: now},
			},
			status: "revoked",
			reason: 6,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := node.New("certificate", nil)
			projectRevocationAssessment(tree, test.assessment)
			status, ok := tree.Resolve("revocation.status")
			if !ok || status.Value != test.status {
				t.Fatalf("status = %#v, want %q", status, test.status)
			}
			covered, ok := tree.Resolve("revocation.coveredReasons")
			if !ok || covered.Value != int(test.assessment.CoveredReasons) {
				t.Fatalf("coveredReasons = %#v", covered)
			}
			reason, present := tree.Resolve("revocation.reasonCode")
			if test.reason == nil {
				if present {
					t.Fatalf("unexpected reasonCode = %#v", reason)
				}
				return
			}
			if !present || reason.Value != test.reason {
				t.Fatalf("reasonCode = %#v, want %v", reason, test.reason)
			}
			projectedTime, ok := tree.Resolve("revocation.revocationTime")
			if !ok || projectedTime.Value != now {
				t.Fatalf("revocationTime = %#v, want %v", projectedTime, now)
			}
		})
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
	parent := testpki.Issue(t, "CRL CA", nil, testpki.CA(), testpki.SubjectKeyID([]byte{0x01, 0x02}))
	leaf := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "subscriber"},
		Issuer:                parent.Cert.Subject,
		SerialNumber:          big.NewInt(2),
		IssuingCertificateURL: []string{testpki.Serve(t, parent.DER)},
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
