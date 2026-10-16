package evaluator

import (
	cryptox509 "crypto/x509"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/crlnode"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	pathpkg "github.com/cavoq/PCL/internal/path"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
	"github.com/cavoq/PCL/internal/testfiles"
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

func TestChainSubjectsProjectTrustAnchor(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.Serial(1))
	intermediate := testpki.Issue(t, "Intermediate", root, testpki.CA(), testpki.Serial(2))
	leaf := testpki.Issue(t, "Leaf", intermediate, testpki.Serial(3))
	info := func(certificate *testpki.Certificate) *cert.Info {
		return &cert.Info{Cert: testpki.ParseZCrypto(t, certificate.DER)}
	}
	chain := []*cert.Info{info(leaf), info(intermediate)}

	projected := func(anchors []*cert.Info) []any {
		var values []any
		for _, subject := range ChainSubjects(Context{
			Registry:     operator.DefaultRegistry(),
			Chain:        chain,
			TrustAnchors: anchors,
		}) {
			if anchor, ok := subject.Tree.Resolve("trustAnchor"); ok {
				values = append(values, anchor.Value)
			} else {
				values = append(values, nil)
			}
		}
		return values
	}

	// The intermediate is a trust anchor although it is not self-signed.
	if got := projected([]*cert.Info{info(intermediate)}); !reflect.DeepEqual(got, []any{false, true}) {
		t.Fatalf("trustAnchor with the intermediate as anchor = %v, want [false true]", got)
	}
	if got := projected([]*cert.Info{info(root)}); !reflect.DeepEqual(got, []any{false, false}) {
		t.Fatalf("trustAnchor with the root as anchor = %v, want [false false]", got)
	}
	if got := projected(nil); !reflect.DeepEqual(got, []any{nil, nil}) {
		t.Fatalf("trustAnchor without anchors = %v, want absent", got)
	}
}

func TestChainComparesDatesInWholeSeconds(t *testing.T) {
	notAfter := time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC)
	certificate := &cert.Info{Cert: &x509.Certificate{NotAfter: notAfter}}
	profile := policy.Policy{
		ID: "validity",
		Rules: []rule.Rule{{
			ID:       "not-expired",
			Target:   "certificate.validity.notAfter",
			Operator: "onOrAfter",
			Severity: rule.SeverityError,
		}},
	}
	verdict := func(now time.Time) string {
		results := Chain(Context{
			Policies:       []policy.Policy{profile},
			Registry:       operator.DefaultRegistry(),
			Chain:          []*cert.Info{certificate},
			ValidationTime: now,
		})
		return results[0].Results[0].Verdict
	}
	if got := verdict(notAfter.Add(5 * time.Millisecond)); got != rule.VerdictPass {
		t.Fatalf("5 ms into the notAfter second: verdict %s, want pass", got)
	}
	if got := verdict(notAfter.Add(time.Second)); got != rule.VerdictFail {
		t.Fatalf("one second after notAfter: verdict %s, want fail", got)
	}
}

func TestChainProjectsAndPropagatesApplicationPurpose(t *testing.T) {
	certificate := &cert.Info{
		Cert: &x509.Certificate{},
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

func TestChainProjectsExplicitPathValidation(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.Serial(1))
	leaf := testpki.Issue(t, "Leaf", root, testpki.Serial(2))
	profile := policy.Policy{
		ID: "path-validation",
		Rules: []rule.Rule{{
			ID:       "path-valid",
			Target:   "certificate.pathValidation.failureSummary",
			Operator: "absent",
			Severity: rule.SeverityError,
			When: &rule.Condition{
				Target: "certificate.pathValidation", Operator: "present",
			},
		}},
	}
	chain := []*cert.Info{{Cert: leaf.Cert}, {Cert: root.Cert}}
	results := Chain(Context{
		Policies:       []policy.Policy{profile},
		Registry:       operator.DefaultRegistry(),
		Chain:          chain,
		Certificates:   chain,
		TrustAnchors:   []*cert.Info{{Cert: root.Cert}},
		ValidationTime: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		PathRevocation: pathpkg.RevocationNone,
	})
	if len(results) != 2 || results[0].Results[0].Verdict != rule.VerdictPass ||
		results[1].Results[0].Verdict != rule.VerdictSkip {
		t.Fatalf("path validation results = %#v", results)
	}

	expired := Chain(Context{
		Policies:       []policy.Policy{profile},
		Registry:       operator.DefaultRegistry(),
		Chain:          chain,
		Certificates:   chain,
		TrustAnchors:   []*cert.Info{{Cert: root.Cert}},
		ValidationTime: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
		PathRevocation: pathpkg.RevocationNone,
	})
	if expired[0].Results[0].Verdict != rule.VerdictFail ||
		len(expired[0].Results[0].Findings) != 1 ||
		!strings.Contains(expired[0].Results[0].Findings[0].Message, "path.validity") {
		t.Fatalf("expired path result = %#v", expired[0].Results[0])
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
		Cert: &x509.Certificate{SerialNumber: big.NewInt(42)},
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
			Cert: &x509.Certificate{SerialNumber: big.NewInt(42)},
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
	registry.Register(evaluationTimeProbe{expected: expected.Truncate(time.Second)})
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
		Chain:          []*cert.Info{{Cert: &x509.Certificate{}}},
		ValidationTime: expected,
	})
	if len(results) != 1 || results[0].Verdict != rule.VerdictPass {
		t.Fatalf("results = %#v, want configured time to reach operators", results)
	}
}

func TestOCSPUsesConfiguredValidationTime(t *testing.T) {
	expected := time.Date(2026, 8, 14, 12, 0, 0, 123, time.UTC)
	registry := operator.NewRegistry()
	registry.Register(evaluationTimeProbe{expected: expected.Truncate(time.Second)})
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
		testfiles.Certs("ocsp-leaf.pem"),
		nil,
	)
	if err != nil || len(leafCertificates) != 1 {
		t.Fatalf("load OCSP leaf: certificates=%d err=%v", len(leafCertificates), err)
	}
	issuerCertificates, err := cert.LoadCertificates(
		testfiles.Certs("ocsp-intermediate.pem"),
		nil,
	)
	if err != nil || len(issuerCertificates) != 1 {
		t.Fatalf("load OCSP issuer: certificates=%d err=%v", len(issuerCertificates), err)
	}
	responses, err := ocsp.GetOCSPs(
		testfiles.OCSPs("good-leaf.ocsp"),
		nil,
	)
	if err != nil || len(responses) != 1 || responses[0] == nil || responses[0].Response == nil {
		t.Fatalf("load OCSP response: responses=%d err=%v", len(responses), err)
	}

	applicable := leafCertificates[0]
	unrelatedCertificate := *applicable.Cert
	unrelatedCertificate.SerialNumber = new(big.Int).Add(applicable.Cert.SerialNumber, big.NewInt(1))
	unrelated := &cert.Info{Cert: &unrelatedCertificate}

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
	registry.Register(evaluationTimeProbe{expected: expected.Truncate(time.Second)})
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

	tree := crlnode.BuildTreeWithChain(revocationList, crlSignerPool(ctx))
	if tree.Children["isCACRL"].Value != true {
		t.Fatalf("isCACRL = %v, want true", tree.Children["isCACRL"].Value)
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

	pol, err := policy.ParseFile(testfiles.Policies("crl-validity.yaml"))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	ctx := Context{
		Policies: []policy.Policy{pol},
		Registry: operator.DefaultRegistry(),
		CRLs:     []*crl.Info{nil, {CRL: nil}, {CRL: valid, FilePath: "test.crl"}},
		Chain:    []*cert.Info{{Cert: signer}},
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

func TestCRLSignerPoolListsChainThenOtherCertificates(t *testing.T) {
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1)}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2)}
	crlSigner := &x509.Certificate{SerialNumber: big.NewInt(3)}
	chain := []*cert.Info{{Cert: leaf}, {Cert: issuer}}

	pool := crlSignerPool(Context{
		Chain:        chain,
		Certificates: []*cert.Info{{Cert: issuer}, {Cert: crlSigner}, nil},
	})
	if len(pool) != 3 || pool[0] != leaf || pool[1] != issuer || pool[2] != crlSigner {
		t.Fatalf("crlSignerPool() = %v, want leaf, issuer, CRL signer", pool)
	}
}

// Building subjects only reads the inputs: certificates the evaluation needs
// are downloaded while acquiring inputs, never here.
func TestSubjectsDoNotDownload(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA())
	unsupplied := testpki.Issue(t, "Unsupplied CA", nil, testpki.CA(), testpki.Serial(2))
	url, hits := testpki.ServeCounted(t, unsupplied.DER)
	leaf := testpki.Issue(t, "Leaf", root, testpki.Serial(3), testpki.IssuingCertificateURLs(url))
	responder := testpki.Issue(t, "Responder", unsupplied, testpki.Serial(4),
		testpki.OCSPSigning(), testpki.IssuingCertificateURLs(url))
	response := testpki.OCSPResponse(t, root, responder, stdocsp.Response{
		Status:       stdocsp.Good,
		SerialNumber: big.NewInt(3),
		ThisUpdate:   testpki.NotBefore,
		NextUpdate:   testpki.NotAfter,
		Certificate:  responder.Std,
	})
	list, err := x509.ParseRevocationList(unsupplied.RevocationList(t, &cryptox509.RevocationList{}))
	if err != nil {
		t.Fatal(err)
	}

	ctx := Context{
		Registry:       operator.DefaultRegistry(),
		Chain:          []*cert.Info{{Cert: leaf.Cert}, {Cert: root.Cert}},
		CRLs:           []*crl.Info{{CRL: list}},
		OCSPs:          []*ocsp.Info{{Response: response}},
		ValidationTime: testpki.NotBefore.AddDate(0, 1, 0),
	}
	_ = ChainSubjects(ctx)
	_ = CRLSubjects(ctx)
	_ = OCSPSubjects(ctx)
	if hits.Load() != 0 {
		t.Fatalf("building subjects made %d CA Issuers requests", hits.Load())
	}
}

func TestPathSignerAuthorizerDecidesEachSignerOnce(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.Serial(1))
	intermediate := testpki.Issue(t, "Intermediate", root, testpki.CA(), testpki.Serial(2))
	leaf := testpki.Issue(t, "Leaf", intermediate, testpki.Serial(3))
	untrusted := testpki.Issue(t, "Untrusted", nil, testpki.CA(), testpki.Serial(4))
	authorizer := newPathSignerAuthorizer(Context{
		Chain:        []*cert.Info{{Cert: leaf.Cert}, {Cert: intermediate.Cert}, {Cert: root.Cert}},
		TrustAnchors: []*cert.Info{{Cert: root.Cert}},
	}, testpki.NotBefore.AddDate(0, 1, 0))

	if !authorizer.AuthorizeCRLSigner(nil, intermediate.Cert, nil) {
		t.Fatal("chain CA with a valid path was not authorized")
	}
	if authorizer.AuthorizeCRLSigner(nil, untrusted.Cert, nil) {
		t.Fatal("signer without a path to the trust anchors was authorized")
	}

	// Without candidates a new path decision would reject the chain CA, so
	// unchanged answers show that both decisions were reused.
	authorizer.candidates = nil
	if !authorizer.AuthorizeCRLSigner(nil, intermediate.Cert, nil) ||
		authorizer.AuthorizeCRLSigner(nil, untrusted.Cert, nil) {
		t.Fatal("cached signer decisions changed")
	}
	if len(authorizer.anchoredSigners) != 2 {
		t.Fatalf("decided %d signers, want 2", len(authorizer.anchoredSigners))
	}
}
