// Package certparse is the single entry point for parsing certificates.
// zcrypto is the primary parser; a narrow compatibility path accepts
// certificates with inherited DSA parameters or CRL distribution points that
// only PCL's strict decoder understands.
package certparse

import (
	"crypto/sha256"
	stdasn1 "encoding/asn1"
	"fmt"
	"math/big"

	"github.com/zmap/zcrypto/dsa"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/x509ext"
)

var (
	dsaPublicKeyOID                 = stdasn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	crlDistributionPointsOID        = stdasn1.ObjectIdentifier{2, 5, 29, 31}
	maskedCRLDistributionPointsOID  = stdasn1.ObjectIdentifier{1, 2, 3, 4}
	ctSCTListOID                    = stdasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	ctPrecertificatePoisonOID       = stdasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	crlDistributionPointsZCryptoOID = zasn1.ObjectIdentifier{2, 5, 29, 31}
)

// ParseCertificate parses one DER certificate. The compatibility path is
// deliberately narrow: it only supplies omitted DSA parameters long enough for
// zcrypto to project the certificate, or hides a CRL distribution point after
// PCL's strict decoder has accepted its original DER. A certificate with
// inherited DSA parameters is returned with zero P, Q, and G; see
// HasInheritedDSAParameters.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	certificate, strictErr := x509.ParseCertificate(der)
	if strictErr == nil {
		return certificate, nil
	}

	original, err := parseCertificateDER(der)
	if err != nil {
		return nil, strictErr
	}

	dsaDER, hasInheritedDSA, dsaErr := rewriteInheritedDSAParameters(der)
	crlDER, maskedCRLIndexes, hasUnsupportedCRLDP, crlErr := rewriteCRLDistributionPoints(der)

	type attempt struct {
		der        []byte
		dsa        bool
		crlIndexes []int
	}
	var attempts []attempt
	if dsaErr == nil && hasInheritedDSA {
		attempts = append(attempts, attempt{der: dsaDER, dsa: true})
	}
	if crlErr == nil && hasUnsupportedCRLDP {
		attempts = append(attempts, attempt{der: crlDER, crlIndexes: maskedCRLIndexes})
	}
	if dsaErr == nil && crlErr == nil && hasInheritedDSA && hasUnsupportedCRLDP {
		combined, _, _, combinedErr := rewriteCRLDistributionPoints(dsaDER)
		if combinedErr == nil {
			attempts = append(attempts, attempt{der: combined, dsa: true, crlIndexes: maskedCRLIndexes})
		}
	}

	for _, candidate := range attempts {
		certificate, err = x509.ParseCertificate(candidate.der)
		if err != nil {
			continue
		}
		if err := restoreCertificateRepresentation(certificate, original, candidate.dsa, candidate.crlIndexes); err != nil {
			continue
		}
		return certificate, nil
	}
	return nil, strictErr
}

type certificateDER struct {
	raw          []byte
	outerFields  [][]byte
	tbsFields    [][]byte
	tbsIndex     int
	issuerIndex  int
	subjectIndex int
	spkiIndex    int
	extIndex     int
}

func parseCertificateDER(der []byte) (certificateDER, error) {
	outer, err := readSequenceElements(der)
	if err != nil || len(outer) != 3 {
		return certificateDER{}, fmt.Errorf("invalid Certificate sequence")
	}
	tbs, err := readSequenceElements(outer[0])
	if err != nil {
		return certificateDER{}, fmt.Errorf("invalid TBSCertificate: %w", err)
	}
	first := 0
	if len(tbs) > 0 && elementTag(tbs[0]) == cryptobyte_asn1.Tag(0).ContextSpecific().Constructed() {
		first++
	}
	if len(tbs) < first+6 {
		return certificateDER{}, fmt.Errorf("incomplete TBSCertificate")
	}

	extIndex := -1
	for index := first + 6; index < len(tbs); index++ {
		if elementTag(tbs[index]) == cryptobyte_asn1.Tag(3).ContextSpecific().Constructed() {
			extIndex = index
			break
		}
	}
	return certificateDER{
		raw:          append([]byte(nil), der...),
		outerFields:  outer,
		tbsFields:    tbs,
		tbsIndex:     0,
		issuerIndex:  first + 2,
		subjectIndex: first + 4,
		spkiIndex:    first + 5,
		extIndex:     extIndex,
	}, nil
}

func rewriteInheritedDSAParameters(der []byte) ([]byte, bool, error) {
	layout, err := parseCertificateDER(der)
	if err != nil {
		return nil, false, err
	}
	spki, err := readSequenceElements(layout.tbsFields[layout.spkiIndex])
	if err != nil || len(spki) != 2 {
		return nil, false, fmt.Errorf("invalid SubjectPublicKeyInfo")
	}
	algorithm, err := readSequenceElements(spki[0])
	if err != nil || len(algorithm) != 1 {
		return nil, false, nil
	}
	identifier, err := readObjectIdentifier(algorithm[0])
	if err != nil || !identifier.Equal(dsaPublicKeyOID) {
		return nil, false, nil
	}

	parameters, err := buildASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1BigInt(big.NewInt(1))
		builder.AddASN1BigInt(big.NewInt(1))
		builder.AddASN1BigInt(big.NewInt(1))
	})
	if err != nil {
		return nil, false, err
	}
	algorithmDER, err := buildSequence(algorithm[0], parameters)
	if err != nil {
		return nil, false, err
	}
	spkiDER, err := buildSequence(algorithmDER, spki[1])
	if err != nil {
		return nil, false, err
	}
	tbs := cloneElements(layout.tbsFields)
	tbs[layout.spkiIndex] = spkiDER
	rewritten, err := rebuildCertificate(layout, tbs)
	return rewritten, err == nil, err
}

func rewriteCRLDistributionPoints(der []byte) ([]byte, []int, bool, error) {
	layout, err := parseCertificateDER(der)
	if err != nil {
		return nil, nil, false, err
	}
	if layout.extIndex < 0 {
		return nil, nil, false, nil
	}
	extensionsDER, err := unwrapExplicitSequence(layout.tbsFields[layout.extIndex], cryptobyte_asn1.Tag(3).ContextSpecific().Constructed())
	if err != nil {
		return nil, nil, false, err
	}
	extensions, err := readSequenceElements(extensionsDER)
	if err != nil {
		return nil, nil, false, err
	}

	var masked []int
	for index, rawExtension := range extensions {
		fields, identifier, value, err := readExtension(rawExtension)
		if err != nil {
			return nil, nil, false, err
		}
		if !identifier.Equal(crlDistributionPointsOID) {
			continue
		}
		if _, err := x509ext.DecodeDistributionPoints(value); err != nil {
			return nil, nil, false, err
		}
		maskedOID, err := marshalObjectIdentifier(maskedCRLDistributionPointsOID)
		if err != nil {
			return nil, nil, false, err
		}
		fields[0] = maskedOID
		extensions[index], err = buildSequence(fields...)
		if err != nil {
			return nil, nil, false, err
		}
		masked = append(masked, index)
	}
	if len(masked) == 0 {
		return nil, nil, false, nil
	}

	extensionsDER, err = buildSequence(extensions...)
	if err != nil {
		return nil, nil, false, err
	}
	extensionsWrapper, err := buildASN1(cryptobyte_asn1.Tag(3).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
		builder.AddBytes(extensionsDER)
	})
	if err != nil {
		return nil, nil, false, err
	}
	tbs := cloneElements(layout.tbsFields)
	tbs[layout.extIndex] = extensionsWrapper
	rewritten, err := rebuildCertificate(layout, tbs)
	return rewritten, masked, err == nil, err
}

func restoreCertificateRepresentation(certificate *x509.Certificate, original certificateDER, inheritedDSA bool, crlIndexes []int) error {
	certificate.Raw = append([]byte(nil), original.raw...)
	certificate.RawTBSCertificate = append([]byte(nil), original.outerFields[original.tbsIndex]...)
	certificate.RawIssuer = append([]byte(nil), original.tbsFields[original.issuerIndex]...)
	certificate.RawSubject = append([]byte(nil), original.tbsFields[original.subjectIndex]...)
	certificate.RawSubjectPublicKeyInfo = append([]byte(nil), original.tbsFields[original.spkiIndex]...)
	certificate.FingerprintMD5 = x509.MD5Fingerprint(certificate.Raw)
	certificate.FingerprintSHA1 = x509.SHA1Fingerprint(certificate.Raw)
	certificate.FingerprintSHA256 = x509.SHA256Fingerprint(certificate.Raw)
	certificate.SPKIFingerprint = x509.SHA256Fingerprint(certificate.RawSubjectPublicKeyInfo)
	certificate.TBSCertificateFingerprint = x509.SHA256Fingerprint(certificate.RawTBSCertificate)
	certificate.FingerprintNoCT = x509.SHA256Fingerprint(tbsWithoutCT(original))
	hasher := sha256.New()
	_, _ = hasher.Write(certificate.RawSubjectPublicKeyInfo)
	_, _ = hasher.Write(certificate.RawSubject)
	certificate.SPKISubjectFingerprint = hasher.Sum(nil)

	if inheritedDSA {
		publicKey, ok := certificate.PublicKey.(*dsa.PublicKey)
		if !ok {
			return fmt.Errorf("rewritten DSA key has type %T", certificate.PublicKey)
		}
		// Explicit zero values cannot pass zcrypto's strict DSA parser, making
		// this an unambiguous marker until cert.ResolveInheritedDSAParameters
		// supplies the issuer's parameters. They also make dsa.Verify fail
		// safely instead of panic.
		publicKey.Parameters = dsa.Parameters{P: new(big.Int), Q: new(big.Int), G: new(big.Int)}
	}

	for _, index := range crlIndexes {
		if index < 0 || index >= len(certificate.Extensions) {
			return fmt.Errorf("restored CRL distribution point index %d is out of range", index)
		}
		certificate.Extensions[index].Id = append(zasn1.ObjectIdentifier(nil), crlDistributionPointsZCryptoOID...)
	}
	if len(crlIndexes) > 0 {
		certificate.ExtensionsMap = make(map[string]pkix.Extension, len(certificate.Extensions))
		for _, extension := range certificate.Extensions {
			certificate.ExtensionsMap[extension.Id.String()] = extension
		}
	}
	return nil
}

func tbsWithoutCT(layout certificateDER) []byte {
	if layout.extIndex < 0 {
		return layout.outerFields[layout.tbsIndex]
	}
	extensionsDER, err := unwrapExplicitSequence(layout.tbsFields[layout.extIndex], cryptobyte_asn1.Tag(3).ContextSpecific().Constructed())
	if err != nil {
		return layout.outerFields[layout.tbsIndex]
	}
	extensions, err := readSequenceElements(extensionsDER)
	if err != nil {
		return layout.outerFields[layout.tbsIndex]
	}
	kept := extensions[:0]
	for _, rawExtension := range extensions {
		_, identifier, _, err := readExtension(rawExtension)
		if err != nil {
			return layout.outerFields[layout.tbsIndex]
		}
		if identifier.Equal(ctSCTListOID) || identifier.Equal(ctPrecertificatePoisonOID) {
			continue
		}
		kept = append(kept, rawExtension)
	}
	if len(kept) == len(extensions) {
		return layout.outerFields[layout.tbsIndex]
	}
	tbs := cloneElements(layout.tbsFields)
	if len(kept) == 0 {
		tbs = append(tbs[:layout.extIndex], tbs[layout.extIndex+1:]...)
	} else {
		extensionsDER, err = buildSequence(kept...)
		if err != nil {
			return layout.outerFields[layout.tbsIndex]
		}
		tbs[layout.extIndex], err = buildASN1(cryptobyte_asn1.Tag(3).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
			builder.AddBytes(extensionsDER)
		})
		if err != nil {
			return layout.outerFields[layout.tbsIndex]
		}
	}
	encoded, err := buildSequence(tbs...)
	if err != nil {
		return layout.outerFields[layout.tbsIndex]
	}
	return encoded
}

func readExtension(raw []byte) ([][]byte, stdasn1.ObjectIdentifier, []byte, error) {
	fields, err := readSequenceElements(raw)
	if err != nil || len(fields) < 2 || len(fields) > 3 {
		return nil, nil, nil, fmt.Errorf("invalid Extension")
	}
	identifier, err := readObjectIdentifier(fields[0])
	if err != nil {
		return nil, nil, nil, err
	}
	valueIndex := 1
	if len(fields) == 3 {
		if elementTag(fields[1]) != cryptobyte_asn1.BOOLEAN {
			return nil, nil, nil, fmt.Errorf("invalid Extension critical field")
		}
		valueIndex = 2
	}
	input := cryptobyte.String(fields[valueIndex])
	var value cryptobyte.String
	if !input.ReadASN1(&value, cryptobyte_asn1.OCTET_STRING) || !input.Empty() {
		return nil, nil, nil, fmt.Errorf("invalid Extension value")
	}
	return fields, identifier, append([]byte(nil), value...), nil
}

func readSequenceElements(der []byte) ([][]byte, error) {
	input := cryptobyte.String(der)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("invalid sequence")
	}
	var elements [][]byte
	for !sequence.Empty() {
		var element cryptobyte.String
		var tag cryptobyte_asn1.Tag
		if !sequence.ReadAnyASN1Element(&element, &tag) {
			return nil, fmt.Errorf("invalid sequence element")
		}
		elements = append(elements, append([]byte(nil), element...))
	}
	return elements, nil
}

func unwrapExplicitSequence(der []byte, tag cryptobyte_asn1.Tag) ([]byte, error) {
	input := cryptobyte.String(der)
	var contents cryptobyte.String
	if !input.ReadASN1(&contents, tag) || !input.Empty() {
		return nil, fmt.Errorf("invalid explicit field")
	}
	return append([]byte(nil), contents...), nil
}

func readObjectIdentifier(der []byte) (stdasn1.ObjectIdentifier, error) {
	input := cryptobyte.String(der)
	var identifier stdasn1.ObjectIdentifier
	if !input.ReadASN1ObjectIdentifier(&identifier) || !input.Empty() {
		return nil, fmt.Errorf("invalid object identifier")
	}
	return identifier, nil
}

func marshalObjectIdentifier(identifier stdasn1.ObjectIdentifier) ([]byte, error) {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1ObjectIdentifier(identifier)
	return builder.Bytes()
}

func rebuildCertificate(layout certificateDER, tbsFields [][]byte) ([]byte, error) {
	tbs, err := buildSequence(tbsFields...)
	if err != nil {
		return nil, err
	}
	outer := cloneElements(layout.outerFields)
	outer[layout.tbsIndex] = tbs
	return buildSequence(outer...)
}

func buildSequence(elements ...[]byte) ([]byte, error) {
	return buildASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		for _, element := range elements {
			builder.AddBytes(element)
		}
	})
}

func buildASN1(tag cryptobyte_asn1.Tag, contents func(*cryptobyte.Builder)) ([]byte, error) {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(tag, contents)
	return builder.Bytes()
}

func elementTag(der []byte) cryptobyte_asn1.Tag {
	if len(der) == 0 {
		return 0
	}
	return cryptobyte_asn1.Tag(der[0])
}

func cloneElements(elements [][]byte) [][]byte {
	cloned := make([][]byte, len(elements))
	for index := range elements {
		cloned[index] = append([]byte(nil), elements[index]...)
	}
	return cloned
}

// HasInheritedDSAParameters reports whether certificate is a DSA certificate
// parsed without its own parameters, which it inherits from its issuer.
func HasInheritedDSAParameters(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	publicKey, ok := certificate.PublicKey.(*dsa.PublicKey)
	return ok && publicKey.P != nil && publicKey.Q != nil && publicKey.G != nil &&
		publicKey.P.Sign() == 0 && publicKey.Q.Sign() == 0 && publicKey.G.Sign() == 0
}
