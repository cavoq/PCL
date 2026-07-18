package ocsp

import (
	"bytes"
	"crypto"
	stdx509 "crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/zmap/zcrypto/x509"
	xocsp "golang.org/x/crypto/ocsp"

	ocspzcrypto "github.com/cavoq/PCL/internal/ocsp/zcrypto"
	sharedzcrypto "github.com/cavoq/PCL/internal/zcrypto"
)

// Status is the accepted revocation state for a certificate. NotApplicable
// means that no supplied response was bound to the certificate and its issuer;
// Unknown means that applicable evidence exists but cannot prove Good or
// Revoked (including stale or unverifiable evidence).
type Status uint8

const (
	StatusNotApplicable Status = iota
	StatusUnknown
	StatusGood
	StatusRevoked
)

// Evidence records each independent condition needed before an OCSP response
// can assert a revocation status for a certificate.
type Evidence struct {
	Info           *Info
	Status         Status
	Applicable     bool
	Current        bool
	IssuerMatched  bool
	SignatureValid bool
}

// Valid reports whether the response is applicable, current, and
// cryptographically authenticated by its CertID issuer (or an authorized
// responder certificate issued by that issuer).
func (e Evidence) Valid() bool {
	return e.Applicable && e.Current && e.IssuerMatched && e.SignatureValid
}

// Assessment contains the evidence available for one certificate.
type Assessment struct {
	Evidence []Evidence
}

// Valid reports whether at least one applicable response is current and
// authenticated, independently of whether its status is Good, Revoked, or
// Unknown.
func (a Assessment) Valid() bool {
	for _, evidence := range a.Evidence {
		if evidence.Valid() {
			return true
		}
	}
	return false
}

// HasGood reports whether at least one accepted response explicitly reports
// Good. It remains separate from Status so conflicting Good and Revoked
// responses can be represented without discarding either fact.
func (a Assessment) HasGood() bool {
	for _, evidence := range a.Evidence {
		if evidence.Valid() && evidence.Status == StatusGood {
			return true
		}
	}
	return false
}

// Status returns the aggregate revocation decision. An accepted Revoked
// response takes precedence over Good. Applicable but unaccepted evidence, or
// an accepted OCSP Unknown response, yields Unknown. With no applicable
// evidence the result is NotApplicable.
func (a Assessment) Status() Status {
	sawApplicable := false
	sawGood := false

	for _, evidence := range a.Evidence {
		if !evidence.Applicable {
			continue
		}
		sawApplicable = true
		if !evidence.Valid() {
			continue
		}
		switch evidence.Status {
		case StatusRevoked:
			return StatusRevoked
		case StatusGood:
			sawGood = true
		}
	}

	if sawGood {
		return StatusGood
	}
	if sawApplicable {
		return StatusUnknown
	}
	return StatusNotApplicable
}

// AssessCertificate binds every supplied response to certificate and its
// issuer candidates and returns explicit evidence for policy adapters.
func AssessCertificate(certificate *x509.Certificate, responses []*Info, issuers []*x509.Certificate, now time.Time) Assessment {
	assessment := Assessment{Evidence: make([]Evidence, 0, len(responses))}
	for _, info := range responses {
		assessment.Evidence = append(assessment.Evidence, assessResponse(certificate, info, issuers, now))
	}
	return assessment
}

func assessResponse(certificate *x509.Certificate, info *Info, issuers []*x509.Certificate, now time.Time) Evidence {
	evidence := Evidence{Info: info, Status: StatusNotApplicable}
	if certificate == nil || certificate.SerialNumber == nil || info == nil || info.Response == nil || info.Response.SerialNumber == nil {
		return evidence
	}

	response := info.Response
	if response.SerialNumber.Cmp(certificate.SerialNumber) != 0 {
		return evidence
	}

	issuer := matchingIssuer(response, issuers)
	if issuer == nil {
		return evidence
	}

	evidence.Applicable = true
	evidence.IssuerMatched = true
	evidence.Current = responseCurrentAt(response, now)
	evidence.SignatureValid = responseSignatureValid(response, issuer)
	evidence.Status = responseStatus(response.Status)
	if !evidence.Valid() {
		evidence.Status = StatusUnknown
	}
	return evidence
}

func matchingIssuer(response *xocsp.Response, candidates []*x509.Certificate) *stdx509.Certificate {
	if response == nil || len(response.Raw) == 0 {
		return nil
	}

	certID, ok := ocspzcrypto.ParseCertID(response.Raw)
	if !ok {
		return nil
	}

	for _, candidate := range candidates {
		standard, err := sharedzcrypto.ToStdCert(candidate)
		if err != nil || standard == nil {
			continue
		}
		if certIDMatchesIssuer(certID, response.IssuerHash, standard) {
			return standard
		}
	}
	return nil
}

func certIDMatchesIssuer(certID ocspzcrypto.CertID, hash crypto.Hash, issuer *stdx509.Certificate) bool {
	if issuer == nil {
		return false
	}
	if hash == 0 {
		hash = crypto.SHA1
	}
	if !hash.Available() {
		return false
	}

	var publicKeyInfo struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return false
	}

	h := hash.New()
	_, _ = h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	h.Reset()
	_, _ = h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	return bytes.Equal(certID.IssuerNameHash, issuerNameHash) && bytes.Equal(certID.IssuerKeyHash, issuerKeyHash)
}

func responseCurrentAt(response *xocsp.Response, now time.Time) bool {
	if response == nil || now.IsZero() || response.ThisUpdate.IsZero() || now.Before(response.ThisUpdate) {
		return false
	}
	return response.NextUpdate.IsZero() || !now.After(response.NextUpdate)
}

func responseSignatureValid(response *xocsp.Response, issuer *stdx509.Certificate) bool {
	if response == nil || issuer == nil {
		return false
	}
	if response.CheckSignatureFrom(issuer) == nil {
		return true
	}

	responder := response.Certificate
	if responder == nil || responder.CheckSignatureFrom(issuer) != nil || !hasOCSPSigningUsage(responder) {
		return false
	}
	return response.CheckSignatureFrom(responder) == nil
}

func hasOCSPSigningUsage(certificate *stdx509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == stdx509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	return false
}

func responseStatus(status int) Status {
	switch status {
	case xocsp.Good:
		return StatusGood
	case xocsp.Revoked:
		return StatusRevoked
	default:
		return StatusUnknown
	}
}
