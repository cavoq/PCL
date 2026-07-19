package zcrypto

import (
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// NonNegativeIntegerValue retains an ASN.1 (0..MAX) INTEGER even when it is
// larger than the platform int used by current profile counters. Int is exact
// only when FitsInt is true; Decimal always contains the exact value.
type NonNegativeIntegerValue struct {
	Int     int
	Decimal string
	FitsInt bool
}

// decodeNonNegativeIntegerContent decodes the contents octets of a DER
// INTEGER constrained to (0..MAX). Values outside the native counter range
// remain structurally valid and are retained exactly in Decimal.
func decodeNonNegativeIntegerContent(content []byte) (NonNegativeIntegerValue, error) {
	if len(content) == 0 {
		return NonNegativeIntegerValue{}, fmt.Errorf("INTEGER has empty contents")
	}
	if content[0]&0x80 != 0 {
		return NonNegativeIntegerValue{}, fmt.Errorf("INTEGER is negative")
	}
	if len(content) > 1 && content[0] == 0 && content[1]&0x80 == 0 {
		return NonNegativeIntegerValue{}, fmt.Errorf("INTEGER has redundant leading zero")
	}

	value := new(big.Int).SetBytes(content)
	maxInt := new(big.Int).SetUint64(uint64(^uint(0) >> 1))
	decoded := NonNegativeIntegerValue{Decimal: value.String()}
	if value.Cmp(maxInt) <= 0 {
		decoded.Int = int(value.Uint64())
		decoded.FitsInt = true
	} else {
		// Saturate the compatibility counter. Semantic consumers must consult
		// FitsInt before treating Int as the encoded value.
		decoded.Int = int(^uint(0) >> 1)
	}
	return decoded, nil
}

func decodeSingleNonNegativeInteger(der []byte) (NonNegativeIntegerValue, error) {
	input := cryptobyte.String(der)
	var content cryptobyte.String
	if !input.ReadASN1(&content, cryptobyte_asn1.INTEGER) || !input.Empty() {
		return NonNegativeIntegerValue{}, fmt.Errorf("invalid INTEGER")
	}
	return decodeNonNegativeIntegerContent(content)
}

func readImplicitNonNegativeInteger(
	input *cryptobyte.String,
	tag cryptobyte_asn1.Tag,
) (value NonNegativeIntegerValue, raw []byte, err error) {
	var element cryptobyte.String
	if !input.ReadASN1Element(&element, tag) {
		return NonNegativeIntegerValue{}, nil, fmt.Errorf("invalid implicitly tagged INTEGER")
	}

	encoded := cryptobyte.String(element)
	var content cryptobyte.String
	if !encoded.ReadASN1(&content, tag) || !encoded.Empty() {
		return NonNegativeIntegerValue{}, nil, fmt.Errorf("invalid implicitly tagged INTEGER")
	}
	value, err = decodeNonNegativeIntegerContent(content)
	if err != nil {
		return NonNegativeIntegerValue{}, nil, err
	}
	return value, append([]byte(nil), element...), nil
}

func integerValueScalar(value NonNegativeIntegerValue) any {
	if value.FitsInt {
		return value.Int
	}
	return value.Decimal
}
