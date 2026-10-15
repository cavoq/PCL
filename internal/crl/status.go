package crl

import (
	"time"

	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
)

// RevocationStatus is the deterministic status established by accepted CRL
// evidence. Unknown is deliberately the zero value: missing, incomplete, or
// rejected evidence never proves a certificate good.
type RevocationStatus uint8

const (
	RevocationUnknown RevocationStatus = iota
	RevocationGood
	RevocationRevoked
)

// ReasonSet is the set of revocation reasons covered by accepted CRLs. It is
// the domain-facing name for the shared RFC 5280 ReasonFlags representation
// and remains distinct from the CRLReason entry ENUMERATED value.
type ReasonSet = x509ext.ReasonMask

const (
	ReasonKeyCompromise      = x509ext.ReasonKeyCompromise
	ReasonCACompromise       = x509ext.ReasonCACompromise
	ReasonAffiliationChanged = x509ext.ReasonAffiliationChanged
	ReasonSuperseded         = x509ext.ReasonSuperseded
	ReasonCessation          = x509ext.ReasonCessation
	ReasonCertificateHold    = x509ext.ReasonCertificateHold
	ReasonPrivilegeWithdrawn = x509ext.ReasonPrivilegeWithdrawn
	ReasonAACompromise       = x509ext.ReasonAACompromise
	AllReasons               = x509ext.AllReasons
)

// EvidenceRejection explains why a supplied CRL did not contribute to the
// revocation decision. These values are stable domain outcomes, not parser
// error strings.
type EvidenceRejection string

const (
	EvidenceAccepted                     EvidenceRejection = ""
	EvidenceMalformed                    EvidenceRejection = "malformed"
	EvidenceUnsupportedCritical          EvidenceRejection = "unsupported-critical-extension"
	EvidenceUnrelated                    EvidenceRejection = "unrelated"
	EvidenceScopeMismatch                EvidenceRejection = "scope-mismatch"
	EvidenceNoNewReasons                 EvidenceRejection = "no-new-reasons"
	EvidenceNotCurrent                   EvidenceRejection = "not-current"
	EvidenceSignerUnavailable            EvidenceRejection = "signer-unavailable"
	EvidenceSignerUnauthorized           EvidenceRejection = "signer-unauthorized"
	EvidenceSignerKeyUsage               EvidenceRejection = "signer-key-usage"
	EvidenceInvalidEntry                 EvidenceRejection = "invalid-entry"
	EvidenceCertificateDistributionPoint EvidenceRejection = "certificate-distribution-point"
)

// SignerAuthorizer makes the final decision about a CRL signer. The crl
// package itself checks the CRL issuer name, AKI, signature and cRLSign
// usage; an authorizer can additionally require, for example, a valid,
// unrevoked signer or a signer path to the target's trust anchor. A nil
// authorizer treats the caller-supplied issuer pool as trusted input. Implementations must return a
// stable decision for the same target, signer, and list during one assessment;
// they must also be concurrency-safe when their Catalog is assessed
// concurrently.
type SignerAuthorizer interface {
	AuthorizeCRLSigner(
		target, signer *x509.Certificate,
		list *x509.RevocationList,
	) bool
}

// SignerAuthorizerFunc adapts a function to SignerAuthorizer.
type SignerAuthorizerFunc func(
	target, signer *x509.Certificate,
	list *x509.RevocationList,
) bool

func (f SignerAuthorizerFunc) AuthorizeCRLSigner(
	target, signer *x509.Certificate,
	list *x509.RevocationList,
) bool {
	return f != nil && f(target, signer, list)
}

type RevocationContext struct {
	Now             time.Time
	Issuers         []*x509.Certificate
	UseDeltas       bool
	AuthorizeSigner SignerAuthorizer
}

// Evidence records one complete-CRL assessment for one certificate
// distribution point, optionally updated by a compatible delta CRL.
type Evidence struct {
	CRL               *x509.RevocationList
	Delta             *x509.RevocationList
	DistributionPoint int
	Fallback          bool
	Applicable        bool
	Accepted          bool
	Reasons           ReasonSet
	Signer            *x509.Certificate
	Rejection         EvidenceRejection
}

// Revocation identifies the accepted entry that proved a certificate
// revoked. ReasonCode is zero when the entry omits reasonCode.
type Revocation struct {
	CRL            *x509.RevocationList
	Delta          *x509.RevocationList
	EntryIndex     int
	ReasonCode     int
	RevocationTime time.Time
}

// Assessment retains the complete-CRL decisions used to derive one
// certificate's status. Evidence records the selected compatible delta, when
// one contributes; unrelated and incompatible deltas are intentionally not
// represented as standalone complete-CRL decisions.
type Assessment struct {
	Evidence       []Evidence
	CoveredReasons ReasonSet
	Revocation     *Revocation
}

// Status returns Revoked when accepted evidence contains a revocation, Good
// only when accepted evidence covers every RFC 5280 reason, and Unknown in
// every other case.
func (a Assessment) Status() RevocationStatus {
	if a.Revocation != nil {
		return RevocationRevoked
	}
	if a.CoveredReasons&AllReasons == AllReasons {
		return RevocationGood
	}
	return RevocationUnknown
}

// StatusForCertificate is the compatibility entry point. New callers should
// retain the Assessment so rejected and partial complete-CRL decisions remain
// observable.
func StatusForCertificate(
	certificate *x509.Certificate,
	lists []*x509.RevocationList,
	ctx RevocationContext,
) RevocationStatus {
	return AssessCertificate(certificate, lists, ctx).Status()
}
