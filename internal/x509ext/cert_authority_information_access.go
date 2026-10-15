package x509ext

import (
	stdasn1 "encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// AccessDescription is one entry of the Authority Information Access
// extension:
//
//	AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
//
//	AccessDescription ::= SEQUENCE {
//	    accessMethod    OBJECT IDENTIFIER,
//	    accessLocation  GeneralName }
type AccessDescription struct {
	Method   string
	Location GeneralName
}

// DecodeAuthorityInformationAccess decodes the access descriptions of an
// Authority Information Access extension value.
func DecodeAuthorityInformationAccess(extValue []byte) ([]AccessDescription, error) {
	input := cryptobyte.String(extValue)
	var encodedDescriptions cryptobyte.String
	if !input.ReadASN1(&encodedDescriptions, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("invalid AuthorityInfoAccessSyntax sequence")
	}
	if encodedDescriptions.Empty() {
		return nil, fmt.Errorf("AuthorityInfoAccessSyntax must not be empty")
	}

	var descriptions []AccessDescription
	for index := 0; !encodedDescriptions.Empty(); index++ {
		description, err := decodeAccessDescription(&encodedDescriptions, index)
		if err != nil {
			return nil, err
		}
		descriptions = append(descriptions, description)
	}
	return descriptions, nil
}

func decodeAccessDescription(input *cryptobyte.String, index int) (AccessDescription, error) {
	var encodedDescription cryptobyte.String
	if !input.ReadASN1(&encodedDescription, cryptobyte_asn1.SEQUENCE) {
		return AccessDescription{}, fmt.Errorf("invalid AccessDescription %d", index)
	}

	var method stdasn1.ObjectIdentifier
	if !encodedDescription.ReadASN1ObjectIdentifier(&method) {
		return AccessDescription{}, fmt.Errorf("invalid accessMethod in AccessDescription %d", index)
	}
	location, err := ReadGeneralName(&encodedDescription)
	if err != nil {
		return AccessDescription{}, fmt.Errorf(
			"invalid accessLocation in AccessDescription %d: %w",
			index,
			err,
		)
	}
	if !encodedDescription.Empty() {
		return AccessDescription{}, fmt.Errorf("unexpected data in AccessDescription %d", index)
	}

	return AccessDescription{
		Method:   method.String(),
		Location: location,
	}, nil
}
