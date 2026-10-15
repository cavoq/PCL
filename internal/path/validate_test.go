package path

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/testpki"
	"github.com/zmap/zcrypto/dsa"
	"github.com/zmap/zcrypto/x509"
)

func TestConstructAndValidateExplicitTrustAnchor(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.Serial(1))
	intermediate := testpki.Issue(t, "Intermediate", root, testpki.CA(), testpki.Serial(2))
	leaf := testpki.Issue(t, "Leaf", intermediate, testpki.Serial(3))

	construction, err := Construct(
		[]*cert.Info{pathInfo(leaf)},
		[]*cert.Info{pathInfo(intermediate)},
		[]*cert.Info{pathInfo(root)},
		10,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !construction.Anchored || len(construction.Chain) != 3 {
		t.Fatalf("construction = %#v, want an anchored three-certificate path", construction)
	}

	result := Validate(Inputs{
		Chain:          construction.Chain,
		TrustAnchors:   []*cert.Info{pathInfo(root)},
		ValidationTime: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Policy:         PolicyInputs{Configured: true},
		RevocationMode: RevocationNone,
	})
	if !result.Valid || !result.Anchored || result.TrustAnchor == nil {
		t.Fatalf("validation = valid %v, anchored %v, failures %q", result.Valid, result.Anchored, result.FailureSummary())
	}
	if len(result.Findings) == 0 {
		t.Fatal("validation returned no structured findings")
	}
}

func TestValidateReportsSignatureFailureWithoutLosingAnchor(t *testing.T) {
	actualRoot := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.Serial(1))
	wrongRoot := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.Serial(2))
	leaf := testpki.Issue(t, "Leaf", actualRoot, testpki.Serial(3))

	construction, err := Construct(
		[]*cert.Info{pathInfo(leaf)},
		nil,
		[]*cert.Info{pathInfo(wrongRoot)},
		10,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !construction.Anchored {
		t.Fatal("name-linked path did not retain the explicit trust anchor")
	}
	result := Validate(Inputs{
		Chain:          construction.Chain,
		TrustAnchors:   []*cert.Info{pathInfo(wrongRoot)},
		ValidationTime: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	if result.Valid || !hasFailedFinding(result, "path.signature") {
		t.Fatalf("validation = valid %v, findings %#v", result.Valid, result.Findings)
	}
}

func TestValidateMaximumPathLengthAndRequiredRevocation(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.Serial(1))
	intermediate := testpki.Issue(t, "Intermediate", root, testpki.CA(), testpki.Serial(2))
	leaf := testpki.Issue(t, "Leaf", intermediate, testpki.Serial(3))
	maximum := 0
	result := Validate(Inputs{
		Chain:             []*cert.Info{pathInfo(leaf), pathInfo(intermediate), pathInfo(root)},
		TrustAnchors:      []*cert.Info{pathInfo(root)},
		ValidationTime:    time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		MaximumPathLength: &maximum,
		RevocationMode:    RevocationRequired,
		CheckRevocation: RevocationCheckerFunc(func(*x509.Certificate) RevocationDecision {
			return RevocationDecision{}
		}),
	})
	if result.Valid || !hasFailedFinding(result, "path.maximum-length") ||
		!hasFailedFinding(result, "path.revocation") {
		t.Fatalf("findings = %#v", result.Findings)
	}
}

func TestValidateIfPresentRevocationSkipsAbsentEvidence(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA())
	leaf := testpki.Issue(t, "Leaf", root)
	result := Validate(Inputs{
		Chain:          []*cert.Info{pathInfo(leaf), pathInfo(root)},
		TrustAnchors:   []*cert.Info{pathInfo(root)},
		ValidationTime: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		RevocationMode: RevocationIfPresent,
		CheckRevocation: RevocationCheckerFunc(func(*x509.Certificate) RevocationDecision {
			return RevocationDecision{Status: RevocationUnknown}
		}),
	})
	if !result.Valid {
		t.Fatalf("optional absent revocation evidence invalidated path: %s", result.FailureSummary())
	}
}

func TestValidateRejectsMalformedProgrammaticInputs(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA())

	withNilCertificate := Validate(Inputs{
		Chain:        []*cert.Info{nil, pathInfo(root)},
		TrustAnchors: []*cert.Info{pathInfo(root)},
	})
	if withNilCertificate.Valid || !hasFailedFinding(withNilCertificate, "path.input") {
		t.Fatalf("nil-certificate validation = %#v", withNilCertificate)
	}

	withInvalidRevocation := Validate(Inputs{
		Chain:          []*cert.Info{pathInfo(root)},
		TrustAnchors:   []*cert.Info{pathInfo(root)},
		RevocationMode: RevocationMode("sometimes"),
	})
	if withInvalidRevocation.Valid || !hasFailedFinding(withInvalidRevocation, "path.revocation-input") {
		t.Fatalf("invalid-revocation validation = %#v", withInvalidRevocation)
	}
}

func pathInfo(certificate *testpki.Certificate) *cert.Info {
	return &cert.Info{Cert: certificate.Cert}
}

func hasFailedFinding(result Result, code string) bool {
	for _, finding := range result.Findings {
		if finding.Code == code && finding.Status == FindingFail {
			return true
		}
	}
	return false
}

func TestConstructAndValidateDoNotResolveDSAParameters(t *testing.T) {
	var loaded []*cert.Info
	for _, file := range []string{
		"ValidDSAParameterInheritanceTest5EE.crt",
		"DSAParametersInheritedCACert.crt",
		"DSACACert.crt",
		"TrustAnchorRootCertificate.crt",
	} {
		infos, err := cert.LoadCertificates(filepath.Join("..", "..", "tests", "pkits", "certs", file), nil)
		if err != nil {
			t.Fatal(err)
		}
		loaded = append(loaded, infos...)
	}
	unresolved := func() bool {
		for _, info := range loaded[:2] {
			if info.Cert.PublicKey.(*dsa.PublicKey).P.Sign() != 0 {
				return false
			}
		}
		return true
	}
	validate := func() Result {
		construction, err := Construct(loaded[:1], loaded[1:3], loaded[3:], 10)
		if err != nil {
			t.Fatal(err)
		}
		return Validate(Inputs{
			Chain:          construction.Chain,
			TrustAnchors:   loaded[3:],
			ValidationTime: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			Policy:         PolicyInputs{Configured: true},
			RevocationMode: RevocationNone,
		})
	}

	result := validate()
	if !unresolved() {
		t.Fatal("path construction or validation changed caller certificates")
	}
	if !hasFailedFinding(result, "path.signature") {
		t.Fatalf("unresolved DSA parameters did not fail closed: %q", result.FailureSummary())
	}

	cert.ResolveInheritedDSAParameters(loaded)
	if result := validate(); !result.Valid {
		t.Fatalf("resolved path is invalid: %q", result.FailureSummary())
	}
}

// TestValidateUnsetRevocationModeIsTheDefault keeps one meaning for an unset
// mode across the CLI, the evaluator and direct callers.
func TestValidateUnsetRevocationModeIsTheDefault(t *testing.T) {
	if RevocationMode("").OrDefault() != DefaultRevocationMode || RevocationRequired.OrDefault() != RevocationRequired {
		t.Fatal("OrDefault does not keep set modes and default unset ones")
	}
	root := testpki.Issue(t, "Root", nil, testpki.CA())
	leaf := testpki.Issue(t, "Leaf", root)
	validate := func(mode RevocationMode) Result {
		return Validate(Inputs{
			Chain:          []*cert.Info{pathInfo(leaf), pathInfo(root)},
			TrustAnchors:   []*cert.Info{pathInfo(root)},
			ValidationTime: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			RevocationMode: mode,
		})
	}
	unset, defaulted, none := validate(""), validate(DefaultRevocationMode), validate(RevocationNone)
	if !reflect.DeepEqual(unset.Findings, defaulted.Findings) {
		t.Fatalf("unset mode findings = %#v, want the default mode's %#v", unset.Findings, defaulted.Findings)
	}
	if reflect.DeepEqual(unset.Findings, none.Findings) {
		t.Fatal("unset mode behaves like none")
	}
}
