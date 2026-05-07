package zcrypto

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/asn1"
)

// TimeEncodingInfo contains ASN.1 time encoding details.
type TimeEncodingInfo struct {
	NotBefore    *asn1.TimeFormatInfo
	NotAfter     *asn1.TimeFormatInfo
}

// ParseValidityEncoding parses the validity period from TBSCertificate
// and returns the ASN.1 encoding information.
func ParseValidityEncoding(rawTBSCertificate []byte) (*TimeEncodingInfo, error) {
	input := cryptobyte.String(rawTBSCertificate)

	var tbsCert cryptobyte.String
	if !input.ReadASN1(&tbsCert, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read TBSCertificate")
	}

	// Skip version (optional, context-specific tag 0)
	tbsCert.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific())

	// Skip serialNumber (INTEGER)
	tbsCert.SkipASN1(cryptobyte_asn1.INTEGER)

	// Skip signature AlgorithmIdentifier
	tbsCert.SkipASN1(cryptobyte_asn1.SEQUENCE)

	// Skip issuer Name
	tbsCert.SkipASN1(cryptobyte_asn1.SEQUENCE)

	// Read validity (SEQUENCE containing notBefore and notAfter)
	var validity cryptobyte.String
	if !tbsCert.ReadASN1(&validity, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read validity")
	}

	info := &TimeEncodingInfo{}

	// Read notBefore (UTCTime or GeneralizedTime)
	var notBeforeDER cryptobyte.String
	var notBeforeTag cryptobyte_asn1.Tag
	if !validity.ReadAnyASN1Element(&notBeforeDER, &notBeforeTag) {
		return nil, fmt.Errorf("failed to read notBefore")
	}

	notBeforeBytes := []byte(notBeforeDER)
	switch int(notBeforeTag) {
	case 23: // UtCTime
		info.NotBefore, _ = asn1.ParseUTCTime(notBeforeBytes)
	case 24: // GeneralizedTime
		info.NotBefore, _ = asn1.ParseGeneralizedTime(notBeforeBytes)
	}

	// Read notAfter (UTCTime or GeneralizedTime)
	var notAfterDER cryptobyte.String
	var notAfterTag cryptobyte_asn1.Tag
	if !validity.ReadAnyASN1Element(&notAfterDER, &notAfterTag) {
		return nil, fmt.Errorf("failed to read notAfter")
	}

	notAfterBytes := []byte(notAfterDER)
	switch int(notAfterTag) {
	case 23: // UTCTime
		info.NotAfter, _ = asn1.ParseUTCTime(notAfterBytes)
	case 24: // GeneralizedTime
		info.NotAfter, _ = asn1.ParseGeneralizedTime(notAfterBytes)
	}

	return info, nil
}

// SubjectDNEncodingInfo contains encoding details for Subject DN attributes.
type SubjectDNEncodingInfo struct {
	Attributes map[string]*asn1.EncodingInfo
}

// ParseSubjectDNEncoding parses Subject DN and returns encoding info for each attribute.
func ParseSubjectDNEncoding(rawSubject []byte) (*SubjectDNEncodingInfo, error) {
	input := cryptobyte.String(rawSubject)

	var name cryptobyte.String
	if !input.ReadASN1(&name, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read Subject DN")
	}

	info := &SubjectDNEncodingInfo{
		Attributes: make(map[string]*asn1.EncodingInfo),
	}

	// Iterate through RelativeDistinguishedName components
	for !name.Empty() {
		var rdn cryptobyte.String
		if !name.ReadASN1(&rdn, cryptobyte_asn1.SET) {
			break
		}

		// Iterate through AttributeTypeAndValue
		for !rdn.Empty() {
			var atv cryptobyte.String
			if !rdn.ReadASN1(&atv, cryptobyte_asn1.SEQUENCE) {
				break
			}

			// Read OID
			var oid cryptobyte.String
			if !atv.ReadASN1(&oid, cryptobyte_asn1.OBJECT_IDENTIFIER) {
				break
			}
			oidStr := oidString(oid)

			// Read value and its encoding tag
			var valueDER cryptobyte.String
			var valueTag cryptobyte_asn1.Tag
			if !atv.ReadAnyASN1Element(&valueDER, &valueTag) {
				break
			}

			// Store encoding info based on tag type
			valueBytes := []byte(valueDER)
			encInfo, _ := parseAttributeValueEncoding(int(valueTag), valueBytes, oidStr)
			if encInfo != nil {
				info.Attributes[oidStr] = encInfo
			}
		}
	}

	return info, nil
}

// parseAttributeValueEncoding parses encoding info for a DN attribute value.
func parseAttributeValueEncoding(tag int, derBytes []byte, oid string) (*asn1.EncodingInfo, error) {
	switch tag {
	case 22: // IA5String
		return asn1.ValidateIA5String(derBytes)
	case 19: // PrintableString
		return asn1.ValidatePrintableString(derBytes)
	case 12: // UTF8String
		// UTF8String is always valid for modern certificates
		return &asn1.EncodingInfo{
			Type:        asn1.EncodingUTF8String,
			TagName:     "UTF8String",
			RawBytes:    derBytes,
			ValidChars:  true,
		}, nil
	case 30: // BMPString
		return &asn1.EncodingInfo{
			Type:        asn1.EncodingBMPString,
			TagName:     "BMPString",
			RawBytes:    derBytes,
			ValidChars:  true,
		}, nil
	default:
		return nil, fmt.Errorf("unknown encoding tag %d for OID %s", tag, oid)
	}
}

// ParseTBSCertSignatureParams parses the signature AlgorithmIdentifier
// from TBSCertificate and returns the parameters state.
func ParseTBSCertSignatureParams(rawTBSCertificate []byte) asn1.ParamsState {
	input := cryptobyte.String(rawTBSCertificate)

	var tbsCert cryptobyte.String
	if !input.ReadASN1(&tbsCert, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Skip version (optional, context-specific tag 0)
	if !tbsCert.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return asn1.ParamsState{}
	}

	// Skip serialNumber (INTEGER)
	if !tbsCert.SkipASN1(cryptobyte_asn1.INTEGER) {
		return asn1.ParamsState{}
	}

	// Read signature AlgorithmIdentifier
	var sigAlgoID cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !tbsCert.ReadAnyASN1Element(&sigAlgoID, &tag) {
		return asn1.ParamsState{}
	}

	return asn1.ParseAlgorithmIDParams(sigAlgoID)
}

// ParseCertSignatureAlgorithmParams parses the outer signatureAlgorithm
// from a certificate and returns the parameters state.
func ParseCertSignatureAlgorithmParams(rawCertificate []byte) asn1.ParamsState {
	input := cryptobyte.String(rawCertificate)

	var cert cryptobyte.String
	if !input.ReadASN1(&cert, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Skip TBSCertificate
	var tbs cryptobyte.String
	if !cert.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Read signatureAlgorithm
	var sigAlgo cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !cert.ReadAnyASN1Element(&sigAlgo, &tag) {
		return asn1.ParamsState{}
	}

	return asn1.ParseAlgorithmIDParams(sigAlgo)
}

// ParseSubjectPublicKeyInfoParams parses the algorithm AlgorithmIdentifier
// from SubjectPublicKeyInfo and returns the parameters state.
func ParseSubjectPublicKeyInfoParams(rawSubjectPublicKeyInfo []byte) asn1.ParamsState {
	input := cryptobyte.String(rawSubjectPublicKeyInfo)

	var spki cryptobyte.String
	if !input.ReadASN1(&spki, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Read algorithm AlgorithmIdentifier
	var algoID cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !spki.ReadAnyASN1Element(&algoID, &tag) {
		return asn1.ParamsState{}
	}

	return asn1.ParseAlgorithmIDParams(algoID)
}

// oidString converts a cryptobyte OID to standard string format (e.g., "2.5.4.3")
func oidString(oid cryptobyte.String) string {
	var components []int

	// First two components are encoded in first byte
	var first byte
	if !oid.ReadUint8(&first) {
		return ""
	}
	components = append(components, int(first/40), int(first%40))

	// Read remaining components (variable length encoding)
	for !oid.Empty() {
		var val int
		if !readOIDComponent(&oid, &val) {
			break
		}
		components = append(components, val)
	}

	// Build string representation
	result := ""
	for i, c := range components {
		if i > 0 {
			result += "."
		}
		result += intToStr(c)
	}
	return result
}

func readOIDComponent(oid *cryptobyte.String, val *int) bool {
	var v int
	for {
		var b byte
		if !oid.ReadUint8(&b) {
			return false
		}
		v = (v << 7) | int(b&0x7f)
		if b&0x80 == 0 {
			break
		}
	}
	*val = v
	return true
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	// Reverse digits
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

// TimeToGeneralizedTime converts a time.Time to ASN.1 GeneralizedTime DER bytes.
// This is used for testing and validation.
func TimeToGeneralizedTime(t time.Time) []byte {
	// GeneralizedTime format: YYYYMMDDHHMMSSZ
	str := t.Format("20060102150405") + "Z"
	return encodeASN1String(24, str)
}

// TimeToUTCTime converts a time.Time to ASN.1 UTCTime DER bytes.
// This is used for testing and validation.
func TimeToUTCTime(t time.Time) []byte {
	// UTCTime format: YYMMDDHHMMSSZ
	str := t.Format("060102150405") + "Z"
	return encodeASN1String(23, str)
}

// encodeASN1String creates a DER-encoded ASN.1 string.
func encodeASN1String(tag int, value string) []byte {
	length := len(value)
	result := make([]byte, 0, 2+len(value))
	result = append(result, byte(tag), byte(length))
	result = append(result, []byte(value)...)
	return result
}

// ParseRawCertificateTimes parses validity times from a raw certificate DER.
// Returns the parsed time values and their encoding formats.
func ParseRawCertificateTimes(rawCert []byte) (notBefore, notAfter time.Time, notBeforeTag, notAfterTag int, err error) {
	input := cryptobyte.String(rawCert)

	var cert cryptobyte.String
	if !input.ReadASN1(&cert, cryptobyte_asn1.SEQUENCE) {
		return time.Time{}, time.Time{}, 0, 0, fmt.Errorf("failed to read certificate")
	}

	// Read TBSCertificate
	var tbs cryptobyte.String
	if !cert.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return time.Time{}, time.Time{}, 0, 0, fmt.Errorf("failed to read TBSCertificate")
	}

	// Skip version
	tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific())
	// Skip serialNumber
	tbs.SkipASN1(cryptobyte_asn1.INTEGER)
	// Skip signature algorithm
	tbs.SkipASN1(cryptobyte_asn1.SEQUENCE)
	// Skip issuer
	tbs.SkipASN1(cryptobyte_asn1.SEQUENCE)

	// Read validity
	var validity cryptobyte.String
	if !tbs.ReadASN1(&validity, cryptobyte_asn1.SEQUENCE) {
		return time.Time{}, time.Time{}, 0, 0, fmt.Errorf("failed to read validity")
	}

	// Parse notBefore
	var nb cryptobyte.String
	var nbTag cryptobyte_asn1.Tag
	if !validity.ReadAnyASN1(&nb, &nbTag) {
		return time.Time{}, time.Time{}, 0, 0, fmt.Errorf("failed to read notBefore")
	}
	notBeforeTag = int(nbTag)

	switch notBeforeTag {
	case 23:
		var utcTime string
		if _, err := stdasn1.Unmarshal([]byte(nb), &utcTime); err == nil {
			notBefore, _ = time.Parse("060102150405Z", utcTime)
		}
	case 24:
		var genTime string
		if _, err := stdasn1.Unmarshal([]byte(nb), &genTime); err == nil {
			notBefore, _ = time.Parse("20060102150405Z", genTime)
		}
	}

	// Parse notAfter
	var na cryptobyte.String
	var naTag cryptobyte_asn1.Tag
	if !validity.ReadAnyASN1(&na, &naTag) {
		return time.Time{}, time.Time{}, 0, 0, fmt.Errorf("failed to read notAfter")
	}
	notAfterTag = int(naTag)

	switch notAfterTag {
	case 23:
		var utcTime string
		if _, err := stdasn1.Unmarshal([]byte(na), &utcTime); err == nil {
			notAfter, _ = time.Parse("060102150405Z", utcTime)
		}
	case 24:
		var genTime string
		if _, err := stdasn1.Unmarshal([]byte(na), &genTime); err == nil {
			notAfter, _ = time.Parse("20060102150405Z", genTime)
		}
	}

	return notBefore, notAfter, notBeforeTag, notAfterTag, nil
}