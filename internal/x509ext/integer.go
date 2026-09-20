// Package x509ext provides format-neutral, strict DER decoders for X.509
// extension structures shared by certificates and CRLs.
package x509ext

import (
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// NonNegativeInteger retains an ASN.1 INTEGER (0..MAX) without truncating it
// to a native integer. Int is exact only when FitsInt is true.
type NonNegativeInteger struct {
	Int     int
	Decimal string
	FitsInt bool
	RawDER  []byte
	Content []byte
}

// DecodeNonNegativeInteger decodes exactly one minimally encoded DER INTEGER
// constrained to (0..MAX).
func DecodeNonNegativeInteger(der []byte) (NonNegativeInteger, error) {
	input := cryptobyte.String(der)
	var content cryptobyte.String
	if !input.ReadASN1(&content, cryptobyte_asn1.INTEGER) || !input.Empty() {
		return NonNegativeInteger{}, fmt.Errorf("invalid INTEGER")
	}
	decoded, err := DecodeNonNegativeIntegerContent(content)
	if err != nil {
		return NonNegativeInteger{}, err
	}
	decoded.RawDER = append([]byte(nil), der...)
	return decoded, nil
}

// DecodeNonNegativeIntegerContent decodes the contents octets of a DER
// INTEGER constrained to (0..MAX).
func DecodeNonNegativeIntegerContent(content []byte) (NonNegativeInteger, error) {
	if len(content) == 0 {
		return NonNegativeInteger{}, fmt.Errorf("INTEGER has empty contents")
	}
	if content[0]&0x80 != 0 {
		return NonNegativeInteger{}, fmt.Errorf("INTEGER is negative")
	}
	if len(content) > 1 && content[0] == 0 && content[1]&0x80 == 0 {
		return NonNegativeInteger{}, fmt.Errorf("INTEGER has redundant leading zero")
	}

	value := new(big.Int).SetBytes(content)
	maxInt := new(big.Int).SetUint64(uint64(^uint(0) >> 1))
	decoded := NonNegativeInteger{
		Decimal: value.String(),
		Content: append([]byte(nil), content...),
	}
	if value.Cmp(maxInt) <= 0 {
		decoded.Int = int(value.Uint64())
		decoded.FitsInt = true
	} else {
		decoded.Int = int(^uint(0) >> 1)
	}
	return decoded, nil
}

// Scalar returns the exact native integer when it fits and its decimal form
// otherwise. It is intended for lossless node projection.
func (v NonNegativeInteger) Scalar() any {
	if v.FitsInt {
		return v.Int
	}
	return v.Decimal
}
