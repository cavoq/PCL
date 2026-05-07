package zcrypto

import (
	"fmt"
	"strings"

	"github.com/cavoq/PCL/internal/node"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ParseAIA parses the Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1)
// and returns a node tree with accessDescriptions.
//
// ASN.1 structure (RFC 5280 4.2.2.1):
//   AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
//   AccessDescription ::= SEQUENCE {
//       accessMethod    OBJECT IDENTIFIER,
//       accessLocation  GeneralName }
//
// GeneralName context-specific tags:
//   0: otherName, 1: rfc822Name, 2: dNSName, 3: x400Address,
//   4: directoryName, 5: ediPartyName, 6: uniformResourceIdentifier,
//   7: iPAddress, 8: registeredID
func ParseAIA(extValue []byte) *node.Node {
	n := node.New("authorityInfoAccess", nil)
	accessDescriptionsNode := node.New("accessDescriptions", nil)
	n.Children["accessDescriptions"] = accessDescriptionsNode

	input := cryptobyte.String(extValue)

	var ads cryptobyte.String
	if !input.ReadASN1(&ads, cryptobyte_asn1.SEQUENCE) {
		return n
	}

	// Empty AIA is invalid per BR
	if len(ads) == 0 {
		n.Children["empty"] = node.New("empty", true)
		return n
	}

	n.Children["empty"] = node.New("empty", false)

	// Track OCSP and CA Issuers presence
	hasOCSP := false
	hasCaIssuers := false

	idx := 0
	for len(ads) > 0 {
		var ad cryptobyte.String
		if !ads.ReadASN1(&ad, cryptobyte_asn1.SEQUENCE) {
			break
		}

		adNode := node.New(fmt.Sprintf("%d", idx), nil)

		// Read accessMethod (OID)
		var accessMethod cryptobyte.String
		if !ad.ReadASN1(&accessMethod, cryptobyte_asn1.OBJECT_IDENTIFIER) {
			break
		}
		methodOID := oidString(accessMethod)
		adNode.Children["accessMethod"] = node.New("accessMethod", methodOID)

		// Track OCSP and CA Issuers
		if methodOID == "1.3.6.1.5.5.7.48.1" { // id-ad-ocsp
			hasOCSP = true
		}
		if methodOID == "1.3.6.1.5.5.7.48.2" { // id-ad-caIssuers
			hasCaIssuers = true
		}

		// Read accessLocation (GeneralName - context-specific tagged)
		var location cryptobyte.String
		var locationTag cryptobyte_asn1.Tag
		if !ad.ReadAnyASN1(&location, &locationTag) {
			break
		}

		locationNode := node.New("accessLocation", nil)
		contextTag := int(locationTag & 0x1F)
		locationNode.Children["type"] = node.New("type", generalNameType(contextTag))
		locationNode.Children["tag"] = node.New("tag", contextTag)

		switch contextTag {
		case 6:
			uri := string(location)
			locationNode.Children["value"] = node.New("value", uri)
			if strings.Contains(uri, ":") {
				scheme := strings.Split(uri, ":")[0]
				locationNode.Children["scheme"] = node.New("scheme", scheme)
			}
		case 2:
			locationNode.Children["value"] = node.New("value", string(location))
		case 7:
			if len(location) == 4 || len(location) == 16 {
				locationNode.Children["value"] = node.New("value", location)
			}
		default:
			locationNode.Children["value"] = node.New("value", location)
		}

		adNode.Children["accessLocation"] = locationNode
		accessDescriptionsNode.Children[fmt.Sprintf("%d", idx)] = adNode
		idx++
	}

	n.Children["count"] = node.New("count", idx)
	n.Children["containsOCSP"] = node.New("containsOCSP", hasOCSP)
	n.Children["containsCaIssuers"] = node.New("containsCaIssuers", hasCaIssuers)

	return n
}

// ParseCRLDP parses the CRL Distribution Points extension (OID 2.5.29.31)
// and returns a node tree with distributionPoints.
//
// ASN.1 structure (RFC 5280 4.2.1.13):
//   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
//   DistributionPoint ::= SEQUENCE {
//       distributionPoint [0] DistributionPointName OPTIONAL,
//       reasons           [1] ReasonFlags OPTIONAL,
//       cRLIssuer         [2] GeneralNames OPTIONAL }
//   DistributionPointName ::= CHOICE {
//       fullName [0] GeneralNames,
//       nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
func ParseCRLDP(extValue []byte) *node.Node {
	n := node.New("cRLDistributionPoints", nil)
	distributionPointsNode := node.New("distributionPoints", nil)
	n.Children["distributionPoints"] = distributionPointsNode

	input := cryptobyte.String(extValue)

	var dps cryptobyte.String
	if !input.ReadASN1(&dps, cryptobyte_asn1.SEQUENCE) {
		return n
	}

	// Empty CRL DP is invalid per BR
	if len(dps) == 0 {
		n.Children["empty"] = node.New("empty", true)
		return n
	}

	n.Children["empty"] = node.New("empty", false)

	idx := 0
	for len(dps) > 0 {
		var dp cryptobyte.String
		if !dps.ReadASN1(&dp, cryptobyte_asn1.SEQUENCE) {
			break
		}

		dpNode := node.New(fmt.Sprintf("%d", idx), nil)

		// Parse DistributionPoint fields
		// [0] distributionPoint, [1] reasons, [2] cRLIssuer
		hasFullName := false
		hasReasons := false
		hasCRLIssuer := false

		for len(dp) > 0 {
			var field cryptobyte.String
			var tag cryptobyte_asn1.Tag
			if !dp.ReadAnyASN1(&field, &tag) {
				break
			}

			contextTag := int(tag & 0x1F)

			switch contextTag {
			case 0: // distributionPoint [0]
				dpNameNode := node.New("distributionPoint", nil)
				// Check if fullName [0] or nameRelativeToCRLIssuer [1]
				var inner cryptobyte.String
				var innerTag cryptobyte_asn1.Tag
				if field.ReadAnyASN1(&inner, &innerTag) {
					innerTagNum := int(innerTag & 0x1F)
					if innerTagNum == 0 {
						// fullName [0] GeneralNames
						fullNameNode := node.New("fullName", nil)
						generalNamesNode := node.New("generalNames", nil)
						uriIdx := 0
						for len(inner) > 0 {
							var name cryptobyte.String
							var nameTag cryptobyte_asn1.Tag
							if !inner.ReadAnyASN1(&name, &nameTag) {
								break
							}
							nameTagNum := int(nameTag & 0x1F)
							gnNode := node.New(fmt.Sprintf("%d", uriIdx), nil)
							gnNode.Children["type"] = node.New("type", generalNameType(nameTagNum))
							gnNode.Children["tag"] = node.New("tag", nameTagNum)
							if nameTagNum == 6 {
								uri := string(name)
								gnNode.Children["value"] = node.New("value", uri)
								if strings.Contains(uri, ":") {
									scheme := strings.Split(uri, ":")[0]
									gnNode.Children["scheme"] = node.New("scheme", scheme)
								}
							} else {
								gnNode.Children["value"] = node.New("value", name)
							}
							generalNamesNode.Children[fmt.Sprintf("%d", uriIdx)] = gnNode
							uriIdx++
							hasFullName = true
						}
						fullNameNode.Children["generalNames"] = generalNamesNode
						fullNameNode.Children["count"] = node.New("count", uriIdx)
						dpNameNode.Children["fullName"] = fullNameNode
					} else if innerTagNum == 1 {
						// nameRelativeToCRLIssuer [1]
						dpNameNode.Children["nameRelativeToCRLIssuer"] = node.New("nameRelativeToCRLIssuer", field)
					}
				}
				dpNode.Children["distributionPoint"] = dpNameNode

			case 1: // reasons [1] ReasonFlags
				reasonsNode := node.New("reasons", nil)
				reasonsNode.Children["present"] = node.New("present", true)
				reasonsNode.Children["raw"] = node.New("raw", field)
				// ReasonFlags is BIT STRING - parse the bits
				if len(field) >= 2 {
					unusedBits := int(field[0])
					reasonsNode.Children["unusedBits"] = node.New("unusedBits", unusedBits)
					if len(field) > 1 {
						reasonsBytes := field[1:]
						reasonsNode.Children["value"] = node.New("value", reasonsBytes)
						// Decode individual reasons (bits 0-9)
						decodeReasonFlags(reasonsNode, reasonsBytes, unusedBits)
					}
				}
				dpNode.Children["reasons"] = reasonsNode
				hasReasons = true

			case 2: // cRLIssuer [2] GeneralNames
				crlIssuerNode := node.New("cRLIssuer", nil)
				crlIssuerNode.Children["present"] = node.New("present", true)
				gnIdx := 0
				for len(field) > 0 {
					var name cryptobyte.String
					var nameTag cryptobyte_asn1.Tag
					if !field.ReadAnyASN1(&name, &nameTag) {
						break
					}
					nameTagNum := int(nameTag & 0x1F)
					gnNode := node.New(fmt.Sprintf("%d", gnIdx), nil)
					gnNode.Children["type"] = node.New("type", generalNameType(nameTagNum))
					gnNode.Children["tag"] = node.New("tag", nameTagNum)
					gnNode.Children["value"] = node.New("value", name)
					crlIssuerNode.Children[fmt.Sprintf("%d", gnIdx)] = gnNode
					gnIdx++
				}
				crlIssuerNode.Children["count"] = node.New("count", gnIdx)
				dpNode.Children["cRLIssuer"] = crlIssuerNode
				hasCRLIssuer = true
			}
		}

		// Mark presence/absence of optional fields
		dpNode.Children["hasFullName"] = node.New("hasFullName", hasFullName)
		dpNode.Children["hasReasons"] = node.New("hasReasons", hasReasons)
		dpNode.Children["hasCRLIssuer"] = node.New("hasCRLIssuer", hasCRLIssuer)

		distributionPointsNode.Children[fmt.Sprintf("%d", idx)] = dpNode
		idx++
	}

	n.Children["count"] = node.New("count", idx)

	return n
}

// generalNameType returns the GeneralName type string for a context-specific tag number
func generalNameType(tag int) string {
	switch tag {
	case 0:
		return "otherName"
	case 1:
		return "rfc822Name"
	case 2:
		return "dNSName"
	case 3:
		return "x400Address"
	case 4:
		return "directoryName"
	case 5:
		return "ediPartyName"
	case 6:
		return "uniformResourceIdentifier"
	case 7:
		return "iPAddress"
	case 8:
		return "registeredID"
	default:
		return "unknown"
	}
}

// decodeReasonFlags decodes the CRL revocation reason flags
// Bits: 0=unused, 1=keyCompromise, 2=cACompromise, 3=affiliationChanged,
// 4=superseded, 5=cessationOfOperation, 6=certificateHold,
// 8=removeFromCRL, 9=privilegeWithdrawn, 10=aACompromise
func decodeReasonFlags(n *node.Node, bytes []byte, unusedBits int) {
	reasonNames := []string{
		"unused",           // bit 0
		"keyCompromise",    // bit 1
		"cACompromise",     // bit 2
		"affiliationChanged", // bit 3
		"superseded",       // bit 4
		"cessationOfOperation", // bit 5
		"certificateHold",  // bit 6
		"",                 // bit 7 (unused)
		"removeFromCRL",    // bit 8
		"privilegeWithdrawn", // bit 9
		"aACompromise",     // bit 10
	}

	for bit := 0; bit < len(reasonNames) && bit < len(bytes)*8-unusedBits; bit++ {
		if reasonNames[bit] == "" {
			continue
		}
		byteIdx := bit / 8
		bitIdx := 7 - (bit % 8)
		if byteIdx < len(bytes) && (bytes[byteIdx]&(1<<bitIdx)) != 0 {
			n.Children[reasonNames[bit]] = node.New(reasonNames[bit], true)
		}
	}
}

// Policy Qualifier Type OIDs
const (
	idQtCps     = "1.3.6.1.5.5.7.2.1" // CPS URI
	idQtUnotice = "1.3.6.1.5.5.7.2.2" // UserNotice
)

// ParseCertPolicies parses the Certificate Policies extension (OID 2.5.29.32)
// and returns a node tree with policyInformations and policyQualifiers.
//
// ASN.1 structure (RFC 5280 4.2.1.4):
//   CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
//   PolicyInformation ::= SEQUENCE {
//       policyIdentifier   OBJECT IDENTIFIER,
//       policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
//   PolicyQualifierInfo ::= SEQUENCE {
//       policyQualifierId  OBJECT IDENTIFIER,
//       qualifier          ANY DEFINED BY policyQualifierId }
//
// Qualifier types:
//   id-qt-cps (1.3.6.1.5.5.7.2.1): CPS URI - IA5String
//   id-qt-unotice (1.3.6.1.5.5.7.2.2): UserNotice - SEQUENCE { noticeRef, explicitText }
func ParseCertPolicies(extValue []byte) *node.Node {
	n := node.New("certificatePolicies", nil)
	policiesNode := node.New("policyInformations", nil)
	n.Children["policyInformations"] = policiesNode

	input := cryptobyte.String(extValue)

	var policies cryptobyte.String
	if !input.ReadASN1(&policies, cryptobyte_asn1.SEQUENCE) {
		return n
	}

	if len(policies) == 0 {
		n.Children["empty"] = node.New("empty", true)
		return n
	}

	idx := 0

	for len(policies) > 0 {
		var policy cryptobyte.String
		if !policies.ReadASN1(&policy, cryptobyte_asn1.SEQUENCE) {
			break
		}

		policyNode := node.New(fmt.Sprintf("%d", idx), nil)

		// Read policyIdentifier (OID)
		var policyOID cryptobyte.String
		if !policy.ReadASN1(&policyOID, cryptobyte_asn1.OBJECT_IDENTIFIER) {
			break
		}
		policyOIDStr := oidString(policyOID)
		policyNode.Children["policyIdentifier"] = node.New("policyIdentifier", policyOIDStr)

		// Add friendly name for known policy OIDs
		friendlyName := policyFriendlyName(policyOIDStr)
		if friendlyName != "" {
			policyNode.Children["name"] = node.New("name", friendlyName)
			// Add policy by friendly name for direct access
			n.Children[friendlyName] = policyNode
		}

		// Add policy by OID as well for direct access (compatibility)
		n.Children[policyOIDStr] = policyNode

		// Read policyQualifiers (OPTIONAL SEQUENCE)
		if len(policy) > 0 {
			qualifiersNode := node.New("policyQualifiers", nil)
			var qualifiers cryptobyte.String
			if policy.ReadASN1(&qualifiers, cryptobyte_asn1.SEQUENCE) {
				qIdx := 0
				for len(qualifiers) > 0 {
					var qualifier cryptobyte.String
					if !qualifiers.ReadASN1(&qualifier, cryptobyte_asn1.SEQUENCE) {
						break
					}

					qNode := node.New(fmt.Sprintf("%d", qIdx), nil)

					// Read policyQualifierId (OID)
					var qOID cryptobyte.String
					if !qualifier.ReadASN1(&qOID, cryptobyte_asn1.OBJECT_IDENTIFIER) {
						break
					}
					qOIDStr := oidString(qOID)
					qNode.Children["policyQualifierId"] = node.New("policyQualifierId", qOIDStr)

					// Parse qualifier based on OID
					if qOIDStr == idQtCps {
						// CPS URI - IA5String
						var cpsURI cryptobyte.String
						if qualifier.ReadASN1(&cpsURI, cryptobyte_asn1.IA5String) {
							uri := string(cpsURI)
							qNode.Children["cpsURI"] = node.New("cpsURI", uri)
							qNode.Children["type"] = node.New("type", "cps")
							// Check encoding
							qNode.Children["encoding"] = node.New("encoding", "ia5String")
							// Extract scheme for convenience
							if strings.Contains(uri, ":") {
								scheme := strings.Split(uri, ":")[0]
								qNode.Children["scheme"] = node.New("scheme", scheme)
							}
						}
					} else if qOIDStr == idQtUnotice {
						// UserNotice - SEQUENCE
						qNode.Children["type"] = node.New("type", "userNotice")
						var userNotice cryptobyte.String
						if qualifier.ReadASN1(&userNotice, cryptobyte_asn1.SEQUENCE) {
							unNode := node.New("userNotice", nil)
							// Parse elements: noticeReference (SEQUENCE) first, then explicitText (string)
							// If first element is not SEQUENCE, it's explicitText
							for len(userNotice) > 0 {
								var element cryptobyte.String
								var elementTag cryptobyte_asn1.Tag
								if !userNotice.ReadAnyASN1(&element, &elementTag) {
									break
								}

								if elementTag == cryptobyte_asn1.SEQUENCE {
									// noticeReference
									nrNode := node.New("noticeReference", nil)
									var org cryptobyte.String
									var noticeNums cryptobyte.String
									if element.ReadASN1(&org, cryptobyte_asn1.SEQUENCE) {
										orgNode := node.New("organization", nil)
										var orgStr cryptobyte.String
										var orgTag cryptobyte_asn1.Tag
										if org.ReadAnyASN1(&orgStr, &orgTag) {
											orgNode.Children["value"] = node.New("value", string(orgStr))
											orgNode.Children["encoding"] = node.New("encoding", asn1StringType(int(orgTag)))
										}
										nrNode.Children["organization"] = orgNode
										if org.ReadASN1(&noticeNums, cryptobyte_asn1.SEQUENCE) {
											numsNode := node.New("noticeNumbers", nil)
											numIdx := 0
											for len(noticeNums) > 0 {
												var num int64
												if noticeNums.ReadASN1Integer(&num) {
													numsNode.Children[fmt.Sprintf("%d", numIdx)] = node.New(fmt.Sprintf("%d", numIdx), num)
													numIdx++
												} else {
													break
												}
											}
											numsNode.Children["count"] = node.New("count", numIdx)
											nrNode.Children["noticeNumbers"] = numsNode
										}
									}
									unNode.Children["noticeReference"] = nrNode
								} else {
									// explicitText - DisplayText (any string type)
									etNode := node.New("explicitText", nil)
									etNode.Children["value"] = node.New("value", string(element))
									etNode.Children["encoding"] = node.New("encoding", asn1StringType(int(elementTag)))
									etNode.Children["tag"] = node.New("tag", int(elementTag))
									unNode.Children["explicitText"] = etNode
								}
							}
							qNode.Children["userNotice"] = unNode
						}
					} else {
						// Unknown qualifier type - store raw bytes
						qNode.Children["type"] = node.New("type", "unknown")
						var raw cryptobyte.String
						var rawTag cryptobyte_asn1.Tag
						if qualifier.ReadAnyASN1(&raw, &rawTag) {
							qNode.Children["raw"] = node.New("raw", raw)
						}
					}

					qualifiersNode.Children[fmt.Sprintf("%d", qIdx)] = qNode
					// Also add by OID for direct access
					qualifiersNode.Children[qOIDStr] = qNode
					qIdx++
				}
				qualifiersNode.Children["count"] = node.New("count", qIdx)
			}
			policyNode.Children["policyQualifiers"] = qualifiersNode
		}

		policiesNode.Children[fmt.Sprintf("%d", idx)] = policyNode
		idx++
	}

	return n
}

// asn1StringType returns the ASN.1 string type name for a tag number
func asn1StringType(tag int) string {
	switch tag {
	case 12:
		return "utf8String"
	case 13:
		return "printableString"
	case 22:
		return "ia5String"
	case 20:
		return "bmpString"
	case 19:
		return "visibleString"
	case 26:
		return "universalString"
	default:
		return "unknown"
	}
}

// policyFriendlyName returns friendly name for known certificate policy OIDs
func policyFriendlyName(oid string) string {
	switch oid {
	// TLS/SSL Server Certificate Policies
	case "2.23.140.1.2.1":
		return "dvPolicy"
	case "2.23.140.1.2.2":
		return "ovPolicy"
	case "2.23.140.1.2.3":
		return "ivPolicy"
	case "2.23.140.1.1":
		return "evPolicy"
	case "2.5.29.32.0":
		return "anyPolicy"
	// Code Signing Policies
	case "2.23.140.1.4.1":
		return "codeSigningPolicy"
	// SMIME Policies - Mailbox-validated
	case "2.23.140.1.5.1.1":
		return "smimeMailboxLegacy"
	case "2.23.140.1.5.1.2":
		return "smimeMailboxMultipurpose"
	case "2.23.140.1.5.1.3":
		return "smimeMailboxStrict"
	// SMIME Policies - Organization-validated
	case "2.23.140.1.5.2.1":
		return "smimeOrgLegacy"
	case "2.23.140.1.5.2.2":
		return "smimeOrgMultipurpose"
	case "2.23.140.1.5.2.3":
		return "smimeOrgStrict"
	// SMIME Policies - Sponsor-validated
	case "2.23.140.1.5.3.1":
		return "smimeSponsorLegacy"
	case "2.23.140.1.5.3.2":
		return "smimeSponsorMultipurpose"
	case "2.23.140.1.5.3.3":
		return "smimeSponsorStrict"
	default:
		return ""
	}
}