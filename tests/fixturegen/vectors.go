package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"time"
)

// vectors writes the DER vectors under tests/vectors, one directory per
// vector: malformed or unusual certificates and CRLs that are easier to build
// in code than with a CA tool. Each is issued by a self-signed CA certificate
// valid from 2026-07-18 11:00 to 2027-07-18 13:00 UTC.
func (f fixtures) vectors() error {
	w := vectorWriter{f}
	for _, vector := range []func(vectorWriter) error{
		vectorCRLInvalidProfile,
		vectorValidRevokedCertificate,
		vectorCertificateAlgorithmMismatch,
		vectorCRLAlgorithmMismatch,
		vectorCRLEntryCriticalExtension,
		vectorCertificateEmptyKeyUsage,
		vectorCertificateEmptyGeneralNames,
		vectorCertificateValidityBoundary,
		vectorCertificateValidityEncodingCutover,
		vectorCertificateSerialLeadingSignOctet,
		vectorCertificateZeroBitIssuerUniqueID,
		vectorCertificateIANSecondInvalidDNSLabel,
		vectorCertificateSANSecondNonIA5Name,
		vectorCRLMissingRequiredFields,
		vectorCRLDNNoncanonicalOrder,
		vectorCertificateDNSecondCommonNameTooLong,
		vectorCertificateDNProjectedAttributes,
		vectorCertificateCountryNameUtf8string,
		vectorCertificateDNNoncanonicalOrder,
		vectorCertificateOrganizationTeletexString,
		vectorCRLEntryReasonUnspecified,
		vectorCRLTBSEncoding,
		rfc4055Vectors,
		tr03116Vectors,
		cabfVectors,
		cabfPolicyVectors,
		cabfAKIVectors,
		cabfWildcardVectors,
		cabfProfileVectors,
	} {
		if err := vector(w); err != nil {
			return err
		}
	}
	return nil
}

// vectorWriter writes the files of one vector directory.
type vectorWriter struct{ f fixtures }

func (w vectorWriter) write(vector, file, blockType string, der []byte) error {
	return w.f.write(filepath.Join("vectors", vector, file), pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func (w vectorWriter) certificate(vector, file string, der []byte) error {
	return w.write(vector, file, "CERTIFICATE", der)
}

func (w vectorWriter) crl(vector string, der []byte) error {
	return w.write(vector, "list.pem", "X509 CRL", der)
}

// withSubject writes a self-signed end entity with the encoded subject.
func (w vectorWriter) withSubject(vector string, subject []byte) error {
	certificate, err := vectorEndEntity(func(template *x509.Certificate) { template.RawSubject = subject })
	if err != nil {
		return err
	}
	return w.certificate(vector, "certificate.pem", certificate.cert.Raw)
}

func vectorCRLInvalidProfile(w vectorWriter) error {
	issuer, err := vectorCA(nil)
	if err != nil {
		return err
	}
	freshest := []byte{
		0x30, 0x10, 0x30, 0x0e, 0xa0, 0x0c, 0xa0, 0x0a,
		0x86, 0x08, 'h', 't', 't', 'p', ':', '/', '/', 'a',
	}
	list, err := revocationList(issuer, &x509.RevocationList{
		ThisUpdate: date(2026, 8, 14, 11, 0, 0),
		NextUpdate: date(2026, 8, 14, 13, 0, 0),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{0x02, 0x01, 0x00}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: []byte{0x30, 0x03, 0x85, 0x01, 0xff}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 46}, Value: freshest},
		},
	})
	if err != nil {
		return err
	}
	return firstError(w.certificate("crl-invalid-profile", "issuer.pem", issuer.cert.Raw),
		w.crl("crl-invalid-profile", list))
}

func vectorValidRevokedCertificate(w vectorWriter) error {
	now := date(2026, 8, 14, 12, 0, 0)
	issuer, err := vectorCA(func(template *x509.Certificate) {
		template.NotBefore = now.Add(-24 * time.Hour)
		template.NotAfter = now.Add(365 * 24 * time.Hour)
	})
	if err != nil {
		return err
	}
	leaf, err := issue(&issuer, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(2)
		template.Subject = pkix.Name{CommonName: "revoked integration leaf"}
		template.NotBefore, template.NotAfter = now.Add(-time.Hour), now.Add(24*time.Hour)
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.BasicConstraintsValid = true
	})
	if err != nil {
		return err
	}
	list, err := revocationList(issuer, &x509.RevocationList{
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   leaf.cert.SerialNumber,
			RevocationTime: now.Add(-30 * time.Minute),
		}},
	})
	if err != nil {
		return err
	}
	return firstError(w.certificate("valid-revoked-certificate", "leaf.pem", leaf.cert.Raw),
		w.certificate("valid-revoked-certificate", "issuer.pem", issuer.cert.Raw),
		w.crl("valid-revoked-certificate", list))
}

func vectorCertificateAlgorithmMismatch(w vectorWriter) error {
	issuer, err := vectorCA(nil)
	if err != nil {
		return err
	}
	der, err := replaceOuterSignatureAlgorithm(issuer.cert.Raw)
	if err != nil {
		return err
	}
	return w.certificate("certificate-algorithm-mismatch", "certificate.pem", der)
}

func vectorCRLAlgorithmMismatch(w vectorWriter) error {
	issuer, err := vectorCA(nil)
	if err != nil {
		return err
	}
	list, err := revocationList(issuer, nil)
	if err != nil {
		return err
	}
	der, err := replaceOuterSignatureAlgorithm(list)
	if err != nil {
		return err
	}
	return firstError(w.certificate("crl-algorithm-mismatch", "issuer.pem", issuer.cert.Raw),
		w.crl("crl-algorithm-mismatch", der))
}

func vectorCRLEntryCriticalExtension(w vectorWriter) error {
	issuer, err := vectorCA(nil)
	if err != nil {
		return err
	}
	list, err := revocationList(issuer, &x509.RevocationList{
		ThisUpdate: date(2026, 7, 18, 11, 0, 0),
		NextUpdate: date(2026, 7, 19, 11, 0, 0),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   big.NewInt(2),
			RevocationTime: date(2026, 7, 18, 12, 0, 0),
			ExtraExtensions: []pkix.Extension{{
				Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{0x05, 0x00},
			}},
		}},
	})
	if err != nil {
		return err
	}
	return w.crl("crl-entry-critical-extension", list)
}

func vectorCertificateEmptyKeyUsage(w vectorWriter) error {
	certificate, err := vectorCA(func(template *x509.Certificate) {
		template.KeyUsage = 0
		template.ExtraExtensions = []pkix.Extension{{
			Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x01, 0x00},
		}}
	})
	if err != nil {
		return err
	}
	return w.certificate("certificate-empty-key-usage", "certificate.pem", certificate.cert.Raw)
}

func vectorCertificateEmptyGeneralNames(w vectorWriter) error {
	certificate, err := vectorEndEntity(func(template *x509.Certificate) {
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 0x00}}}
	})
	if err != nil {
		return err
	}
	return w.certificate("certificate-empty-general-names", "certificate.pem", certificate.cert.Raw)
}

func vectorCertificateValidityBoundary(w vectorWriter) error {
	boundary := date(2026, 7, 18, 12, 0, 0)
	certificate, err := vectorCA(func(template *x509.Certificate) {
		template.NotBefore, template.NotAfter = boundary, boundary
	})
	if err != nil {
		return err
	}
	return w.certificate("certificate-validity-boundary", "certificate.pem", certificate.cert.Raw)
}

func vectorCertificateValidityEncodingCutover(w vectorWriter) error {
	certificate, err := vectorCA(func(template *x509.Certificate) {
		template.NotBefore = date(2049, 12, 31, 23, 59, 59)
		template.NotAfter = date(2050, 1, 1, 0, 0, 0)
	})
	if err != nil {
		return err
	}
	return w.certificate("certificate-validity-encoding-cutover", "certificate.pem", certificate.cert.Raw)
}

func vectorCertificateSerialLeadingSignOctet(w vectorWriter) error {
	certificate, err := vectorCA(nil)
	if err != nil {
		return err
	}
	der, err := rewriteTBSCertificate(certificate.cert.Raw, func(fields [][]byte) ([][]byte, error) {
		if len(fields) < 2 || len(fields[1]) == 0 || fields[1][0] != 0x02 {
			return nil, fmt.Errorf("TBSCertificate serialNumber field is missing")
		}
		// A 20-octet magnitude with the high bit set needs a leading
		// zero sign octet, making the encoding 21 octets.
		serial, err := asn1.Marshal(new(big.Int).SetBytes(append([]byte{0x80}, make([]byte, 19)...)))
		fields[1] = serial
		return fields, err
	})
	if err != nil {
		return err
	}
	if der, err = resign(der, certificate.key); err != nil {
		return err
	}
	return w.certificate("certificate-serial-leading-sign-octet", "certificate.pem", der)
}

func vectorCertificateZeroBitIssuerUniqueID(w vectorWriter) error {
	certificate, err := vectorCA(nil)
	if err != nil {
		return err
	}
	der, err := rewriteTBSCertificate(certificate.cert.Raw, func(fields [][]byte) ([][]byte, error) {
		// issuerUniqueID is [1] IMPLICIT BIT STRING; a content octet of
		// zero is a present identifier of zero bits.
		insertAt := len(fields)
		for index, field := range fields {
			if len(field) > 0 && field[0] == 0xa3 {
				insertAt = index
				break
			}
		}
		return append(fields[:insertAt:insertAt], append([][]byte{{0x81, 0x01, 0x00}}, fields[insertAt:]...)...), nil
	})
	if err != nil {
		return err
	}
	if der, err = resign(der, certificate.key); err != nil {
		return err
	}
	return w.certificate("certificate-zero-bit-issuer-unique-id", "certificate.pem", der)
}

func vectorCertificateIANSecondInvalidDNSLabel(w vectorWriter) error {
	valid := element(0x82, []byte("valid.example"))
	invalid := element(0x82, []byte{'i', 'n', 'v', 'a', 'l', 'i', 'd', 0xe9, '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'})
	certificate, err := vectorEndEntity(func(template *x509.Certificate) {
		template.ExtraExtensions = []pkix.Extension{{
			Id: asn1.ObjectIdentifier{2, 5, 29, 18}, Value: element(0x30, append(valid, invalid...)),
		}}
	})
	if err != nil {
		return err
	}
	return w.certificate("certificate-ian-second-invalid-dns-label", "certificate.pem", certificate.cert.Raw)
}

func vectorCertificateSANSecondNonIA5Name(w vectorWriter) error {
	certificate, err := vectorEndEntity(func(template *x509.Certificate) {
		template.DNSNames = []string{"valid.example", "nonascii.example"}
	})
	if err != nil {
		return err
	}
	// The name is patched after signing; the signature no longer
	// matters to the SAN repertoire checks.
	der := bytes.Clone(certificate.cert.Raw)
	at := bytes.Index(der, []byte("nonascii.example"))
	if at < 0 {
		return fmt.Errorf("generated SAN name not found in certificate DER")
	}
	der[at] = 0xe9
	return w.certificate("certificate-san-second-non-ia5-name", "certificate.pem", der)
}

func vectorCRLMissingRequiredFields(w vectorWriter) error {
	issuer, err := vectorCA(nil)
	if err != nil {
		return err
	}
	list, err := revocationList(issuer, nil)
	if err != nil {
		return err
	}
	der, err := removeCRLRequiredFields(list)
	if err != nil {
		return err
	}
	return firstError(w.certificate("crl-missing-required-fields", "issuer.pem", issuer.cert.Raw),
		w.crl("crl-missing-required-fields", der))
}

func vectorCRLDNNoncanonicalOrder(w vectorWriter) error {
	issuer, err := vectorCA(func(template *x509.Certificate) { template.RawSubject = nonCanonicalName() })
	if err != nil {
		return err
	}
	list, err := revocationList(issuer, nil)
	if err != nil {
		return err
	}
	return firstError(w.certificate("crl-dn-noncanonical-order", "issuer.pem", issuer.cert.Raw),
		w.crl("crl-dn-noncanonical-order", list))
}

func vectorCertificateDNSecondCommonNameTooLong(w vectorWriter) error {
	return w.withSubject("certificate-dn-second-common-name-too-long", rawName(
		nameAttribute{commonName, asn1.TagUTF8String, "first"},
		nameAttribute{commonName, asn1.TagUTF8String, strings.Repeat("x", 65)},
	))
}

func vectorCertificateDNProjectedAttributes(w vectorWriter) error {
	return w.withSubject("certificate-dn-projected-attributes", rawName(
		nameAttribute{givenName, asn1.TagUTF8String, strings.Repeat("g", 65)},
		nameAttribute{surname, asn1.TagUTF8String, strings.Repeat("s", 65)},
		nameAttribute{emailAddress, asn1.TagIA5String, "not-an-email-address"},
		nameAttribute{domainComponent, asn1.TagIA5String, strings.Repeat("d", 64)},
	))
}

func vectorCertificateCountryNameUtf8string(w vectorWriter) error {
	return w.withSubject("certificate-country-name-utf8string", rawName(
		nameAttribute{countryName, asn1.TagUTF8String, "DE"},
	))
}

// vectorCertificateOrganizationTeletexString is an end entity whose
// organizationName is a TeletexString, which RFC 5280 4.1.2.4 does not allow
// a conforming CA to use for end-entity subjects.
func vectorCertificateOrganizationTeletexString(w vectorWriter) error {
	return w.withSubject("certificate-organization-teletexstring", rawName(
		nameAttribute{organization, asn1.TagT61String, "Teletex Org"},
		nameAttribute{commonName, asn1.TagUTF8String, "teletex organization"},
	))
}

// vectorCRLEntryReasonUnspecified lists a certificate with the reasonCode
// unspecified (0), which RFC 5280 5.3.1 says should be omitted instead. Go
// refuses to encode a zero reason code, so the entry is issued with
// keyCompromise (1), patched to 0 and signed again.
func vectorCRLEntryReasonUnspecified(w vectorWriter) error {
	issuer, err := vectorCA(nil)
	if err != nil {
		return err
	}
	list, err := revocationList(issuer, &x509.RevocationList{
		ThisUpdate: date(2026, 7, 18, 11, 0, 0),
		NextUpdate: date(2026, 7, 19, 11, 0, 0),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   big.NewInt(42),
			RevocationTime: date(2026, 7, 18, 10, 0, 0),
			ReasonCode:     1,
		}},
	})
	if err != nil {
		return err
	}
	keyCompromise := []byte{0x06, 0x03, 0x55, 0x1d, 0x15, 0x04, 0x03, 0x0a, 0x01, 0x01}
	if bytes.Count(list, keyCompromise) != 1 {
		return fmt.Errorf("crl-entry-reason-unspecified: reasonCode extension not found once")
	}
	unspecified := append(bytes.Clone(keyCompromise[:len(keyCompromise)-1]), 0x00)
	if list, err = resign(bytes.Replace(list, keyCompromise, unspecified, 1), issuer.key); err != nil {
		return err
	}
	return firstError(w.certificate("crl-entry-reason-unspecified", "issuer.pem", issuer.cert.Raw),
		w.crl("crl-entry-reason-unspecified", list))
}

// vectorCRLTBSEncoding writes CRLs whose TBSCertList breaks one encoding
// rule of RFC 5280 5.1.2 each: no version field (v1, rejected when loaded),
// a GeneralizedTime thisUpdate before 2050, a UTCTime nextUpdate without
// seconds and a GeneralizedTime revocationDate with a zone offset. next-update-2050.crl is
// conforming and has a GeneralizedTime nextUpdate. Fields are rewritten
// after Go encoded the CRL, then signed again.
func vectorCRLTBSEncoding(w vectorWriter) error {
	issuer, err := vectorCA(nil)
	if err != nil {
		return err
	}
	template := func(nextUpdate time.Time) *x509.RevocationList {
		return &x509.RevocationList{
			ThisUpdate: date(2026, 7, 18, 11, 0, 0),
			NextUpdate: nextUpdate,
			RevokedCertificateEntries: []x509.RevocationListEntry{{
				SerialNumber:   big.NewInt(42),
				RevocationTime: date(2026, 7, 18, 10, 0, 0),
			}},
		}
	}
	list, err := revocationList(issuer, template(date(2026, 7, 19, 11, 0, 0)))
	if err != nil {
		return err
	}
	late, err := revocationList(issuer, template(date(2050, 1, 1, 0, 0, 0)))
	if err != nil {
		return err
	}
	const (
		version, thisUpdate, nextUpdate, revoked = 0, 3, 4, 5
	)
	files := map[string]func([][]byte) [][]byte{
		"version-absent.crl": func(fields [][]byte) [][]byte { return fields[1:] },
		"this-update-generalizedtime.crl": func(fields [][]byte) [][]byte {
			fields[thisUpdate] = element(0x18, []byte("20260718110000Z"))
			return fields
		},
		"next-update-no-seconds.crl": func(fields [][]byte) [][]byte {
			fields[nextUpdate] = element(0x17, []byte("2607191100Z"))
			return fields
		},
		"revocation-date-offset.crl": func(fields [][]byte) [][]byte {
			entry := append(element(0x02, []byte{42}), element(0x18, []byte("20260718120000+0200"))...)
			fields[revoked] = sequence(sequence(entry))
			return fields
		},
	}
	errs := []error{
		w.certificate("crl-tbs-encoding", "issuer.pem", issuer.cert.Raw),
		w.write("crl-tbs-encoding", "next-update-2050.crl", "X509 CRL", late),
	}
	for file, rewrite := range files {
		der, err := rewriteTBSCertificate(list, func(fields [][]byte) ([][]byte, error) {
			if len(fields) != 7 || fields[version][0] != 0x02 {
				return nil, fmt.Errorf("%s: unexpected TBSCertList layout", file)
			}
			return rewrite(fields), nil
		})
		if err == nil {
			der, err = resign(der, issuer.key)
		}
		if err != nil {
			return err
		}
		errs = append(errs, w.write("crl-tbs-encoding", file, "X509 CRL", der))
	}
	return firstError(errs...)
}

func vectorCertificateDNNoncanonicalOrder(w vectorWriter) error {
	return w.withSubject("certificate-dn-noncanonical-order", nonCanonicalName())
}

// vectorCA issues the self-signed CA certificate the vectors are built on,
// changed by configure when set.
func vectorCA(configure func(template *x509.Certificate)) (issued, error) {
	return issue(nil, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(1)
		template.Subject = pkix.Name{CommonName: "integration-generated"}
		template.SubjectKeyId = []byte{0x01, 0x02, 0x03}
		template.NotBefore, template.NotAfter = date(2026, 7, 18, 11, 0, 0), date(2027, 7, 18, 13, 0, 0)
		template.IsCA, template.BasicConstraintsValid = true, true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if configure != nil {
			configure(template)
		}
	})
}

// vectorEndEntity is vectorCA as a self-signed end entity without a subject
// key identifier.
func vectorEndEntity(configure func(template *x509.Certificate)) (issued, error) {
	return vectorCA(func(template *x509.Certificate) {
		template.IsCA = false
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.SubjectKeyId = nil
		configure(template)
	})
}

// revocationList signs template, or an empty CRL valid for a day from
// 2026-07-18 11:00 UTC when nil, with issuer's key.
func revocationList(issuer issued, template *x509.RevocationList) ([]byte, error) {
	if template == nil {
		template = &x509.RevocationList{ThisUpdate: date(2026, 7, 18, 11, 0, 0), NextUpdate: date(2026, 7, 19, 11, 0, 0)}
	}
	if template.Number == nil {
		template.Number = big.NewInt(1)
	}
	return x509.CreateRevocationList(rand.Reader, template, issuer.cert, issuer.key)
}

var (
	commonName      = asn1.ObjectIdentifier{2, 5, 4, 3}
	countryName     = asn1.ObjectIdentifier{2, 5, 4, 6}
	organization    = asn1.ObjectIdentifier{2, 5, 4, 10}
	surname         = asn1.ObjectIdentifier{2, 5, 4, 4}
	givenName       = asn1.ObjectIdentifier{2, 5, 4, 42}
	emailAddress    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	domainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

type nameAttribute struct {
	identifier asn1.ObjectIdentifier
	tag        int
	value      string
}

// rawName encodes one attribute per RDN with the given string tags.
func rawName(attributes ...nameAttribute) []byte {
	rdns := make(pkix.RDNSequence, 0, len(attributes))
	for _, attribute := range attributes {
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{{
			Type:  attribute.identifier,
			Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: attribute.tag, Bytes: []byte(attribute.value)},
		}})
	}
	der, err := asn1.Marshal(rdns)
	if err != nil {
		panic(err)
	}
	return der
}

// nonCanonicalName is one RDN with a commonName and an organizationName in
// descending DER order, which a SET OF must not use.
func nonCanonicalName() []byte {
	attribute := func(identifier asn1.ObjectIdentifier) []byte {
		der, err := asn1.Marshal(pkix.AttributeTypeAndValue{
			Type:  identifier,
			Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte("subject")},
		})
		if err != nil {
			panic(err)
		}
		return der
	}
	first, second := attribute(commonName), attribute(organization)
	if bytes.Compare(first, second) < 0 {
		first, second = second, first
	}
	return element(0x30, element(0x31, append(first, second...)))
}

// element encodes a DER element with a short length.
func element(tag byte, content []byte) []byte {
	if len(content) >= 128 {
		panic("element only supports short lengths")
	}
	return append([]byte{tag, byte(len(content))}, content...)
}

func sequence(content []byte) []byte {
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
	if err != nil {
		panic(err)
	}
	return der
}

type signedEnvelope struct {
	TBS       asn1.RawValue
	Algorithm asn1.RawValue
	Signature asn1.RawValue
}

func decodeSignedEnvelope(der []byte) (signedEnvelope, error) {
	var envelope signedEnvelope
	if rest, err := asn1.Unmarshal(der, &envelope); err != nil || len(rest) != 0 {
		return envelope, fmt.Errorf("decode signed envelope: rest=%x err=%w", rest, err)
	}
	return envelope, nil
}

// replaceOuterSignatureAlgorithm sets the outer signatureAlgorithm of a
// signed certificate or CRL to sha384WithRSAEncryption, mismatching the TBS.
func replaceOuterSignatureAlgorithm(der []byte) ([]byte, error) {
	envelope, err := decodeSignedEnvelope(der)
	if err != nil {
		return nil, err
	}
	var outer struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	if rest, err := asn1.Unmarshal(envelope.Algorithm.FullBytes, &outer); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("decode outer AlgorithmIdentifier: rest=%x err=%w", rest, err)
	}
	outer.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	outerDER, err := asn1.Marshal(outer)
	if err != nil {
		return nil, err
	}
	content := append(bytes.Clone(envelope.TBS.FullBytes), outerDER...)
	return sequence(append(content, envelope.Signature.FullBytes...)), nil
}

func rewriteTBSCertificate(der []byte, rewrite func([][]byte) ([][]byte, error)) ([]byte, error) {
	envelope, err := decodeSignedEnvelope(der)
	if err != nil {
		return nil, err
	}
	var fields [][]byte
	for content := envelope.TBS.Bytes; len(content) > 0; {
		var field asn1.RawValue
		rest, err := asn1.Unmarshal(content, &field)
		if err != nil {
			return nil, fmt.Errorf("decode TBSCertificate field: %w", err)
		}
		fields = append(fields, bytes.Clone(content[:len(content)-len(rest)]))
		content = rest
	}
	if fields, err = rewrite(fields); err != nil {
		return nil, err
	}
	content := append(sequence(bytes.Join(fields, nil)), envelope.Algorithm.FullBytes...)
	return sequence(append(content, envelope.Signature.FullBytes...)), nil
}

// resign replaces the sha256WithRSAEncryption signature of a certificate
// whose TBSCertificate was rewritten, so it still verifies with key.
func resign(der []byte, key crypto.Signer) ([]byte, error) {
	envelope, err := decodeSignedEnvelope(der)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(envelope.TBS.FullBytes)
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	bitString, err := asn1.Marshal(asn1.BitString{Bytes: signature, BitLength: len(signature) * 8})
	if err != nil {
		return nil, err
	}
	content := append(bytes.Clone(envelope.TBS.FullBytes), envelope.Algorithm.FullBytes...)
	return sequence(append(content, bitString...)), nil
}

// removeCRLRequiredFields drops nextUpdate and the extensions that RFC 5280
// requires of a conforming CRL.
func removeCRLRequiredFields(der []byte) ([]byte, error) {
	envelope, err := decodeSignedEnvelope(der)
	if err != nil {
		return nil, err
	}
	var tbs struct {
		Raw                 asn1.RawContent
		Version             int `asn1:"optional,default:0"`
		Signature           pkix.AlgorithmIdentifier
		Issuer              asn1.RawValue
		ThisUpdate          time.Time
		NextUpdate          time.Time                 `asn1:"optional"`
		RevokedCertificates []pkix.RevokedCertificate `asn1:"optional"`
		Extensions          []pkix.Extension          `asn1:"tag:0,optional,explicit"`
	}
	if rest, err := asn1.Unmarshal(envelope.TBS.FullBytes, &tbs); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("decode TBSCertList: rest=%x err=%w", rest, err)
	}
	tbs.Raw, tbs.NextUpdate, tbs.Extensions = nil, time.Time{}, nil
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	content := append(bytes.Clone(tbsDER), envelope.Algorithm.FullBytes...)
	return sequence(append(content, envelope.Signature.FullBytes...)), nil
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
