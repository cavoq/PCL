package zcrypto

import (
	"fmt"

	"github.com/cavoq/PCL/internal/x509ext"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// NonNegativeIntegerValue retains the historical certificate decoder name
// while using the shared X.509 extension representation.
type NonNegativeIntegerValue = x509ext.NonNegativeInteger

// decodeNonNegativeIntegerContent decodes the contents octets of a DER
// INTEGER constrained to (0..MAX). Values outside the native counter range
// remain structurally valid and are retained exactly in Decimal.
func decodeNonNegativeIntegerContent(content []byte) (NonNegativeIntegerValue, error) {
	return x509ext.DecodeNonNegativeIntegerContent(content)
}

func decodeSingleNonNegativeInteger(der []byte) (NonNegativeIntegerValue, error) {
	return x509ext.DecodeNonNegativeInteger(der)
}

func readImplicitNonNegativeInteger(
	input *cryptobyte.String,
	tag cryptobyte_asn1.Tag,
) (value NonNegativeIntegerValue, raw []byte, err error) {
	var element cryptobyte.String
	if !input.ReadASN1Element(&element, tag) {
		return NonNegativeIntegerValue{}, nil, fmt.Errorf("invalid implicitly tagged INTEGER")
	}

	encoded := element
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
