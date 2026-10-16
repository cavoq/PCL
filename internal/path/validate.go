// Package path constructs and validates RFC 5280 certification paths. Path
// construction is deliberately separate from deterministic validation.
package path

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/finding"
	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/cavoq/PCL/internal/x509ext"
)

// FindingStatus is retained as the path-domain name for a shared finding
// status.
type FindingStatus = finding.Status

const (
	FindingPass = finding.StatusPass
	FindingFail = finding.StatusFail
	FindingSkip = finding.StatusSkip
)

// RevocationMode controls how revocation evidence affects a path decision.
type RevocationMode string

const (
	RevocationNone      RevocationMode = "none"
	RevocationIfPresent RevocationMode = "if-present"
	RevocationRequired  RevocationMode = "required"

	// DefaultRevocationMode is the mode of an unset RevocationMode: supplied
	// revocation evidence is applied, and its absence is not a failure.
	DefaultRevocationMode = RevocationIfPresent
)

// OrDefault returns mode, or DefaultRevocationMode when mode is unset.
func (mode RevocationMode) OrDefault() RevocationMode {
	if mode == "" {
		return DefaultRevocationMode
	}
	return mode
}

// RevocationStatus is the mechanism-independent status returned to the path
// domain by the existing CRL/OCSP assessment adapters.
type RevocationStatus string

const (
	RevocationUnknown RevocationStatus = "unknown"
	RevocationGood    RevocationStatus = "good"
	RevocationRevoked RevocationStatus = "revoked"
)

// RevocationDecision preserves whether evidence was actually available, so
// if-present can distinguish absence from rejected or incomplete evidence.
type RevocationDecision struct {
	Available bool             `json:"available" yaml:"available"`
	Status    RevocationStatus `json:"status" yaml:"status"`
	Details   string           `json:"details,omitempty" yaml:"details,omitempty"`
}

// RevocationChecker adapts revocation processing to path validation.
type RevocationChecker interface {
	CheckRevocation(*x509.Certificate) RevocationDecision
}

// RevocationCheckerFunc adapts a function to RevocationChecker.
type RevocationCheckerFunc func(*x509.Certificate) RevocationDecision

func (check RevocationCheckerFunc) CheckRevocation(certificate *x509.Certificate) RevocationDecision {
	if check == nil {
		return RevocationDecision{}
	}
	return check(certificate)
}

// Inputs are all external RFC 5280 path-validation inputs. Chain is ordered
// target-to-top and may include a trust-anchor certificate as its final item.
// TrustAnchors are trusted out of band and are never validated as ordinary
// path certificates.
type Inputs struct {
	Chain              []*cert.Info
	TrustAnchors       []*cert.Info
	ValidationTime     time.Time
	Policy             PolicyInputs
	MaximumPathLength  *int
	ApplicationPurpose string
	// PeerNames are reference identities the target certificate must
	// present in its subjectAltName (RFC 9525).
	PeerNames       []cert.PeerName
	RevocationMode  RevocationMode
	CheckRevocation RevocationChecker
}

// Finding is the path-domain name for one structured validation decision.
type Finding = finding.Finding

// Result is the deterministic decision for one constructed path.
type Result struct {
	Valid       bool       `json:"valid" yaml:"valid"`
	Anchored    bool       `json:"anchored" yaml:"anchored"`
	Findings    []Finding  `json:"findings" yaml:"findings"`
	Target      *cert.Info `json:"-" yaml:"-"`
	TrustAnchor *cert.Info `json:"-" yaml:"-"`
}

// FailureSummary returns a compact, stable explanation suitable for terminal
// rule details. Structured callers should consume Findings directly.
func (result Result) FailureSummary() string {
	var failures []string
	for _, finding := range result.Findings {
		if finding.Status == FindingFail {
			failures = append(failures, finding.Code+": "+finding.Message)
		}
	}
	return strings.Join(failures, "; ")
}

// Validate deterministically validates one supplied path against explicit
// trust anchors. It never downloads certificates or constructs another path.
func Validate(inputs Inputs) Result {
	result := Result{Valid: true}
	chain := slices.Clone(inputs.Chain)
	anchors := nonNilInfos(inputs.TrustAnchors)
	if len(chain) == 0 {
		result.add(Finding{
			Code: "path.input", Reference: "RFC5280 6.1.1", Status: FindingFail,
			CertificateIndex: -1, Message: "the certification path is empty",
		})
		return result
	}
	for index, info := range chain {
		if info != nil && info.Cert != nil {
			continue
		}
		result.add(Finding{
			Code: "path.input", Reference: "RFC5280 6.1.1", Status: FindingFail,
			CertificateIndex: index, Message: "the certification path contains a nil certificate",
		})
		return result
	}
	mode := inputs.RevocationMode.OrDefault()
	if mode != RevocationNone && mode != RevocationIfPresent && mode != RevocationRequired {
		result.add(Finding{
			Code: "path.revocation-input", Reference: "RFC5280 6.1.1", Status: FindingFail,
			CertificateIndex: -1, Message: "the revocation mode is invalid",
			Details: map[string]any{"mode": inputs.RevocationMode},
		})
		return result
	}
	result.Target = chain[0]

	anchor, included := selectTrustAnchor(chain[len(chain)-1], anchors)
	if anchor == nil {
		result.add(Finding{
			Code: "path.trust-anchor", Reference: "RFC5280 6.1.1", Status: FindingFail,
			CertificateIndex: -1, Message: "the supplied path does not terminate at an explicit trust anchor",
		})
		return result
	}
	result.Anchored, result.TrustAnchor = true, anchor
	result.add(Finding{
		Code: "path.trust-anchor", Reference: "RFC5280 6.1.1", Status: FindingPass,
		CertificateIndex: -1, Message: "the path terminates at an explicit trust anchor",
		Details: map[string]any{"subject": anchor.Cert.Subject.String()},
	})

	for _, name := range inputs.PeerNames {
		result.add(certificateFinding(
			"path.peer-name", "RFC9525 6.3", 0, chain[0].Cert,
			cert.PeerNameMatches(chain[0].Cert, name),
			"certificate presents the requested peer name "+name.String(),
			"certificate does not present the requested peer name "+name.String(),
			map[string]any{"kind": string(name.Kind), "name": name.Value},
		))
	}

	processed := chain
	if included {
		processed = chain[:len(chain)-1]
	}
	if inputs.MaximumPathLength != nil {
		validateMaximumPathLength(&result, processed, *inputs.MaximumPathLength)
	}

	now := inputs.ValidationTime
	if now.IsZero() {
		now = time.Now()
	}
	for index, info := range processed {
		certificate := info.Cert
		validateValidity(&result, index, certificate, now)
		validateCriticalExtensions(&result, index, certificate)
		if inputs.ApplicationPurpose != "" {
			result.add(certificateFinding(
				"path.application-purpose", "RFC5280 6.1.3, 4.2.1.12", index, certificate,
				cert.ApplicationPurposeValid(info, inputs.ApplicationPurpose),
				"certificate permits the requested application purpose",
				"certificate does not permit the requested application purpose",
				map[string]any{"purpose": inputs.ApplicationPurpose},
			))
		}

		issuer := anchor.Cert
		if index+1 < len(processed) {
			issuer = processed[index+1].Cert
		}
		validateIssuerBinding(&result, index, certificate, issuer)
		if mode != RevocationNone {
			validateRevocation(&result, index, certificate, mode, inputs.CheckRevocation)
		}
	}

	for index := 1; index < len(processed); index++ {
		certificate := processed[index].Cert
		result.add(certificateFinding(
			"path.ca-authorized", "RFC5280 6.1.4(k),(n)", index, certificate,
			cert.CanSignCertificates(certificate),
			"issuer is authorized to sign certificates",
			"issuer is not an authorized certificate-signing CA",
			nil,
		))
		result.add(certificateFinding(
			"path.path-length", "RFC5280 6.1.4(l),(m)", index, certificate,
			cert.PathLenConstraintValid(processed[index], processed),
			"path length constraints are satisfied",
			"path length constraint is exceeded or malformed",
			nil,
		))
	}

	for index, info := range processed {
		result.add(certificateFinding(
			"path.name-constraints", "RFC5280 6.1.3(b),(c), 6.1.4(g)", index, info.Cert,
			cert.NameConstraintsValid(info, processed),
			"name constraints are satisfied",
			"name constraints reject the certificate or are malformed",
			nil,
		))
	}

	policyCertificates := make([]*x509.Certificate, 0, len(processed))
	for index := len(processed) - 1; index >= 0; index-- {
		policyCertificates = append(policyCertificates, processed[index].Cert)
	}
	policyValid, policyErr := ValidatePolicies(policyCertificates, inputs.Policy)
	policyMessage := "certificate policy processing succeeded"
	if policyErr != nil {
		policyMessage = "certificate policy processing failed: " + policyErr.Error()
	} else if !policyValid {
		policyMessage = "certificate policy processing rejected the path"
	}
	result.add(Finding{
		Code: "path.certificate-policies", Reference: "RFC5280 6.1.3-6.1.5",
		Status: status(policyErr == nil && policyValid), CertificateIndex: -1,
		Message: policyMessage,
		Details: map[string]any{"initialPolicySet": inputs.Policy.Normalized().InitialPolicySet},
	})
	return result
}

func (result *Result) add(finding Finding) {
	result.Findings = append(result.Findings, finding)
	if finding.Status == FindingFail {
		result.Valid = false
	}
}

func selectTrustAnchor(top *cert.Info, anchors []*cert.Info) (*cert.Info, bool) {
	if top == nil || top.Cert == nil {
		return nil, false
	}
	for _, anchor := range anchors {
		if cert.SameCertificate(top.Cert, anchor.Cert) {
			return anchor, true
		}
	}

	candidates := slices.Clone(anchors)
	slices.SortFunc(candidates, func(left, right *cert.Info) int {
		leftFingerprint := sha256.Sum256(left.Cert.Raw)
		rightFingerprint := sha256.Sum256(right.Cert.Raw)
		return bytes.Compare(leftFingerprint[:], rightFingerprint[:])
	})
	for _, anchor := range candidates {
		if x509asn1.NamesMatchOrText(
			top.Cert.RawIssuer,
			anchor.Cert.RawSubject,
			top.Cert.Issuer.String(),
			anchor.Cert.Subject.String(),
		) && cert.SignedBy(top.Cert, anchor.Cert) {
			return anchor, false
		}
	}
	return nil, false
}

func validateMaximumPathLength(result *Result, processed []*cert.Info, maximum int) {
	if maximum < 0 {
		result.add(Finding{
			Code: "path.maximum-length", Reference: "RFC5280 6.1.1", Status: FindingFail,
			CertificateIndex: -1, Message: "maximum path length must not be negative",
		})
		return
	}
	count := 0
	for index := 1; index < len(processed); index++ {
		if !cert.IsSelfIssued(processed[index].Cert) {
			count++
		}
	}
	result.add(Finding{
		Code: "path.maximum-length", Reference: "RFC5280 6.1.1", Status: status(count <= maximum),
		CertificateIndex: -1,
		Message:          choose(count <= maximum, "caller maximum path length is satisfied", "caller maximum path length is exceeded"),
		Details:          map[string]any{"actual": count, "maximum": maximum},
	})
}

func validateValidity(result *Result, index int, certificate *x509.Certificate, now time.Time) {
	valid := certificate != nil && !now.Before(certificate.NotBefore) && !now.After(certificate.NotAfter)
	result.add(certificateFinding(
		"path.validity", "RFC5280 6.1.3(a)(2)", index, certificate, valid,
		"certificate is valid at the validation time",
		"certificate is not valid at the validation time",
		map[string]any{"validationTime": now},
	))
}

func validateCriticalExtensions(result *Result, index int, certificate *x509.Certificate) {
	valid := certificate != nil && x509ext.CertificateCriticalExtensionsProcessable(certificate.Extensions)
	result.add(certificateFinding(
		"path.critical-extensions", "RFC5280 6.1.3(a)(4), 6.1.4", index, certificate, valid,
		"all critical certificate extensions are processed",
		"a critical certificate extension is duplicate, malformed, or unprocessed",
		nil,
	))
}

func validateIssuerBinding(result *Result, index int, certificate, issuer *x509.Certificate) {
	nameMatches := certificate != nil && issuer != nil && x509asn1.NamesMatchOrText(
		certificate.RawIssuer,
		issuer.RawSubject,
		certificate.Issuer.String(),
		issuer.Subject.String(),
	)
	result.add(certificateFinding(
		"path.issuer-name", "RFC5280 6.1.3(a)(4), 7.1", index, certificate, nameMatches,
		"issuer name matches the issuer certificate subject",
		"issuer name does not match the issuer certificate subject",
		nil,
	))
	signatureValid := certificate != nil && issuer != nil && cert.SignedBy(certificate, issuer)
	result.add(certificateFinding(
		"path.signature", "RFC5280 6.1.3(a)(1)", index, certificate, signatureValid,
		"certificate signature is valid",
		"certificate signature is invalid",
		nil,
	))
}

func validateRevocation(
	result *Result,
	index int,
	certificate *x509.Certificate,
	mode RevocationMode,
	checker RevocationChecker,
) {
	if checker == nil {
		findingStatus := FindingSkip
		message := "no revocation checker was supplied"
		if mode == RevocationRequired {
			findingStatus = FindingFail
			message = "revocation status is required but no checker was supplied"
		}
		result.add(Finding{
			Code: "path.revocation", Reference: "RFC5280 6.3", Status: findingStatus,
			CertificateIndex: index, CertificateSubject: certificateSubject(certificate), Message: message,
		})
		return
	}
	decision := checker.CheckRevocation(certificate)
	if !decision.Available && mode == RevocationIfPresent {
		result.add(Finding{
			Code: "path.revocation", Reference: "RFC5280 6.3", Status: FindingSkip,
			CertificateIndex: index, CertificateSubject: certificateSubject(certificate),
			Message: "no revocation evidence was supplied for the certificate",
		})
		return
	}
	valid := decision.Status == RevocationGood
	message := "revocation evidence establishes that the certificate is good"
	switch decision.Status {
	case RevocationRevoked:
		message = "revocation evidence establishes that the certificate is revoked"
	case RevocationUnknown:
		message = "revocation evidence does not establish certificate status"
	}
	result.add(Finding{
		Code: "path.revocation", Reference: "RFC5280 6.3", Status: status(valid),
		CertificateIndex: index, CertificateSubject: certificateSubject(certificate), Message: message,
		Details: map[string]any{"status": decision.Status, "assessment": decision.Details},
	})
}

func certificateFinding(
	code, reference string,
	index int,
	certificate *x509.Certificate,
	valid bool,
	passMessage, failMessage string,
	details map[string]any,
) Finding {
	return Finding{
		Code: code, Reference: reference, Status: status(valid), CertificateIndex: index,
		CertificateSubject: certificateSubject(certificate),
		Message:            choose(valid, passMessage, failMessage), Details: details,
	}
}

func certificateSubject(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}
	return certificate.Subject.String()
}

func status(valid bool) FindingStatus {
	if valid {
		return FindingPass
	}
	return FindingFail
}

func choose(condition bool, yes, no string) string {
	if condition {
		return yes
	}
	return no
}

func nonNilInfos(infos []*cert.Info) []*cert.Info {
	result := make([]*cert.Info, 0, len(infos))
	for _, info := range infos {
		if info != nil && info.Cert != nil {
			result = append(result, info)
		}
	}
	return result
}
