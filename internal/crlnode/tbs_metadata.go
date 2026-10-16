package crlnode

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/cavoq/PCL/internal/x509node"
)

// tbsCertListMetadata holds the time encodings that the decoded
// x509.RevocationList does not keep. The version needs no projection: the
// CRL parser accepts only v2.
type tbsCertListMetadata struct {
	ThisUpdate      x509asn1.TimeEncoding
	NextUpdate      *x509asn1.TimeEncoding
	RevocationDates []x509asn1.TimeEncoding
}

// parseTBSCertListMetadata walks the TBSCertList of RFC 5280 5.1.
func parseTBSCertListMetadata(rawTBSCertList []byte) (tbsCertListMetadata, error) {
	var metadata tbsCertListMetadata
	input := cryptobyte.String(rawTBSCertList)
	var tbs cryptobyte.String
	if !input.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return metadata, fmt.Errorf("failed to read TBSCertList")
	}
	if !tbs.SkipOptionalASN1(cryptobyte_asn1.INTEGER) {
		return metadata, fmt.Errorf("failed to read version")
	}
	for _, field := range []string{"signature AlgorithmIdentifier", "issuer"} {
		if !tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) {
			return metadata, fmt.Errorf("failed to read %s", field)
		}
	}
	thisUpdate, err := x509asn1.ReadTime(&tbs, "thisUpdate")
	if err != nil {
		return metadata, err
	}
	metadata.ThisUpdate = thisUpdate
	if tbs.PeekASN1Tag(cryptobyte_asn1.UTCTime) || tbs.PeekASN1Tag(cryptobyte_asn1.GeneralizedTime) {
		nextUpdate, err := x509asn1.ReadTime(&tbs, "nextUpdate")
		if err != nil {
			return metadata, err
		}
		metadata.NextUpdate = &nextUpdate
	}
	if tbs.PeekASN1Tag(cryptobyte_asn1.SEQUENCE) {
		var entries cryptobyte.String
		if !tbs.ReadASN1(&entries, cryptobyte_asn1.SEQUENCE) {
			return metadata, fmt.Errorf("failed to read revokedCertificates")
		}
		for !entries.Empty() {
			var entry cryptobyte.String
			if !entries.ReadASN1(&entry, cryptobyte_asn1.SEQUENCE) || !entry.SkipASN1(cryptobyte_asn1.INTEGER) {
				return metadata, fmt.Errorf("failed to read revokedCertificates entry")
			}
			revocationDate, err := x509asn1.ReadTime(&entry, "revocationDate")
			if err != nil {
				return metadata, err
			}
			metadata.RevocationDates = append(metadata.RevocationDates, revocationDate)
		}
	}
	return metadata, nil
}

// projectTBSCertListMetadata adds the encoding facts of thisUpdate,
// nextUpdate and each revocationDate to their decoded nodes. A TBSCertList
// the walk cannot read keeps the decoded values without encoding facts, so
// rules on the encoding fail on the missing facts.
func projectTBSCertListMetadata(root *node.Node, rawTBSCertList []byte) {
	metadata, err := parseTBSCertListMetadata(rawTBSCertList)
	if err != nil {
		return
	}
	if thisUpdate := root.Children["thisUpdate"]; thisUpdate != nil {
		x509node.AddTimeEncoding(thisUpdate, metadata.ThisUpdate)
	}
	if nextUpdate := root.Children["nextUpdate"]; nextUpdate != nil && metadata.NextUpdate != nil {
		x509node.AddTimeEncoding(nextUpdate, *metadata.NextUpdate)
	}
	revoked := root.Children["revokedCertificates"]
	if revoked == nil {
		return
	}
	for index, encoding := range metadata.RevocationDates {
		entry := revoked.Children[fmt.Sprintf("%d", index)]
		if entry == nil || entry.Children["revocationDate"] == nil {
			continue
		}
		x509node.AddTimeEncoding(entry.Children["revocationDate"], encoding)
	}
}
