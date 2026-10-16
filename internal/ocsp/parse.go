package ocsp

import (
	stdx509 "crypto/x509"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/x509asn1"
)

// ParseResponse parses a DER OCSP response like golang.org/x/crypto/ocsp,
// without checking it against an issuer. x/crypto also verifies the
// response with an embedded responder certificate while parsing; it does
// not know RSASSA-PSS, so it rejects every such response that embeds its
// responder. Those are parsed without the embedded certificates, which are
// then parsed separately. The signature is decided later, for every
// response, by the evidence assessment.
func ParseResponse(der []byte) (*xocsp.Response, error) {
	response, err := xocsp.ParseResponse(der, nil)
	if err == nil || ParseOCSPSignatureAlgorithmParams(der).OID != x509asn1.RSASSAPSS {
		return response, err
	}
	stripped, certificates, ok := withoutCertificates(der)
	if !ok || len(certificates) == 0 {
		return nil, err
	}
	response, strippedErr := xocsp.ParseResponse(stripped, nil)
	if strippedErr != nil {
		return nil, err
	}
	responder, certificateErr := stdx509.ParseCertificate(certificates[0])
	if certificateErr != nil {
		return nil, fmt.Errorf("parsing the embedded OCSP responder certificate: %w", certificateErr)
	}
	response.Certificate = responder
	response.Raw = der
	return response, nil
}

// withoutCertificates re-encodes an OCSPResponse without the certs of its
// BasicOCSPResponse and returns the DER of those certificates.
func withoutCertificates(der []byte) ([]byte, [][]byte, bool) {
	input := cryptobyte.String(der)
	var response, status, outer, responseBytes, responseType, basicOctets cryptobyte.String
	if !input.ReadASN1(&response, cryptobyte_asn1.SEQUENCE) || !input.Empty() ||
		!response.ReadASN1Element(&status, cryptobyte_asn1.ENUM) ||
		!response.ReadASN1(&outer, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) || !response.Empty() ||
		!outer.ReadASN1(&responseBytes, cryptobyte_asn1.SEQUENCE) || !outer.Empty() ||
		!responseBytes.ReadASN1Element(&responseType, cryptobyte_asn1.OBJECT_IDENTIFIER) ||
		!responseBytes.ReadASN1(&basicOctets, cryptobyte_asn1.OCTET_STRING) || !responseBytes.Empty() {
		return nil, nil, false
	}

	var basic, tbs, algorithm, signature cryptobyte.String
	if !basicOctets.ReadASN1(&basic, cryptobyte_asn1.SEQUENCE) || !basicOctets.Empty() ||
		!basic.ReadASN1Element(&tbs, cryptobyte_asn1.SEQUENCE) ||
		!basic.ReadASN1Element(&algorithm, cryptobyte_asn1.SEQUENCE) ||
		!basic.ReadASN1Element(&signature, cryptobyte_asn1.BIT_STRING) {
		return nil, nil, false
	}
	var certificates [][]byte
	certsTag := cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()
	if basic.PeekASN1Tag(certsTag) {
		var certsOuter, certs cryptobyte.String
		if !basic.ReadASN1(&certsOuter, certsTag) ||
			!certsOuter.ReadASN1(&certs, cryptobyte_asn1.SEQUENCE) || !certsOuter.Empty() {
			return nil, nil, false
		}
		for !certs.Empty() {
			var certificate cryptobyte.String
			if !certs.ReadASN1Element(&certificate, cryptobyte_asn1.SEQUENCE) {
				return nil, nil, false
			}
			certificates = append(certificates, certificate)
		}
	}
	if !basic.Empty() {
		return nil, nil, false
	}

	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(status)
		b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddBytes(responseType)
				b.AddASN1(cryptobyte_asn1.OCTET_STRING, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddBytes(tbs)
						b.AddBytes(algorithm)
						b.AddBytes(signature)
					})
				})
			})
		})
	})
	stripped, err := builder.Bytes()
	return stripped, certificates, err == nil
}
