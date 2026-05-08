package operator

import (
	"bytes"
	"crypto"
	stdx509 "crypto/x509"
	"encoding/asn1"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/zcrypto"
)

type OCSPValid struct{}

func (OCSPValid) Name() string { return "ocspValid" }

func (OCSPValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasOCSPs() || !ctx.HasChain() {
		return false, nil
	}

	var certSerial string
	if ctx.HasCert() {
		certSerial = ctx.Cert.Cert.SerialNumber.String()
	}
	accepted := false

	for _, ocspInfo := range ctx.OCSPs {
		if ocspInfo.Response == nil {
			continue
		}
		resp := ocspInfo.Response

		if certSerial != "" {
			if resp.SerialNumber == nil || resp.SerialNumber.String() != certSerial {
				continue
			}
		}

		if ctx.Now.Before(resp.ThisUpdate) {
			continue
		}
		if !resp.NextUpdate.IsZero() && ctx.Now.After(resp.NextUpdate) {
			continue
		}

		verified := false
		for _, certInfo := range ctx.Chain {
			if certInfo.Cert == nil {
				continue
			}
			stdCert, err := zcrypto.ToStdCert(certInfo.Cert)
			if err != nil || stdCert == nil {
				continue
			}
			if resp.CheckSignatureFrom(stdCert) == nil && responseMatchesIssuer(resp, stdCert) {
				verified = true
				break
			}
		}
		if verified {
			accepted = true
		}
	}

	return accepted, nil
}

type NotRevokedOCSP struct{}

func (NotRevokedOCSP) Name() string { return "notRevokedOCSP" }

func (NotRevokedOCSP) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}

	if len(ctx.OCSPs) == 0 {
		return true, nil
	}

	certSerial := ctx.Cert.Cert.SerialNumber.String()
	matched := false
	good := false

	for _, ocspInfo := range ctx.OCSPs {
		if ocspInfo.Response == nil {
			continue
		}
		resp := ocspInfo.Response

		if resp.SerialNumber == nil || resp.SerialNumber.String() != certSerial {
			continue
		}

		matched = true
		if resp.Status == ocsp.Revoked {
			return false, nil
		}
		if resp.Status == ocsp.Good {
			good = true
		}
	}

	if good {
		return true, nil
	}
	return !matched, nil
}

type OCSPGood struct{}

func (OCSPGood) Name() string { return "ocspGood" }

func (OCSPGood) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}

	if len(ctx.OCSPs) == 0 {
		return false, nil
	}

	certSerial := ctx.Cert.Cert.SerialNumber.String()

	for _, ocspInfo := range ctx.OCSPs {
		if ocspInfo.Response == nil {
			continue
		}
		resp := ocspInfo.Response

		if resp.SerialNumber == nil || resp.SerialNumber.String() != certSerial {
			continue
		}

		if resp.Status == ocsp.Good {
			return true, nil
		}
	}

	return false, nil
}

func responseMatchesIssuer(resp *ocsp.Response, issuer *stdx509.Certificate) bool {
	certID, ok := parseOCSPCertID(resp.Raw)
	if !ok {
		return false
	}
	return certID.matches(resp.IssuerHash, issuer)
}

type ocspCertID struct {
	IssuerNameHash []byte
	IssuerKeyHash  []byte
}

func (id ocspCertID) matches(hash crypto.Hash, issuer *stdx509.Certificate) bool {
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
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	h.Reset()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	return bytes.Equal(id.IssuerNameHash, issuerNameHash) && bytes.Equal(id.IssuerKeyHash, issuerKeyHash)
}

func parseOCSPCertID(raw []byte) (ocspCertID, bool) {
	var outer ocspResponseASN1
	if _, err := asn1.Unmarshal(raw, &outer); err != nil {
		return ocspCertID{}, false
	}
	if len(outer.ResponseBytes.Response) == 0 {
		return ocspCertID{}, false
	}

	var basic basicOCSPResponseASN1
	if _, err := asn1.Unmarshal(outer.ResponseBytes.Response, &basic); err != nil {
		return ocspCertID{}, false
	}
	if len(basic.TBSResponseData.Responses) == 0 {
		return ocspCertID{}, false
	}

	certID := basic.TBSResponseData.Responses[0].CertID
	return ocspCertID{
		IssuerNameHash: certID.IssuerNameHash,
		IssuerKeyHash:  certID.IssuerKeyHash,
	}, true
}

type ocspResponseASN1 struct {
	Status        asn1.Enumerated
	ResponseBytes responseBytesASN1 `asn1:"explicit,tag:0,optional"`
}

type responseBytesASN1 struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicOCSPResponseASN1 struct {
	TBSResponseData    responseDataASN1
	SignatureAlgorithm asn1.RawValue
	Signature          asn1.BitString
}

type responseDataASN1 struct {
	Version     int `asn1:"explicit,tag:0,optional,default:0"`
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []singleResponseASN1
}

type singleResponseASN1 struct {
	CertID certIDASN1
}

type certIDASN1 struct {
	HashAlgorithm  asn1.RawValue
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   asn1.RawValue
}
