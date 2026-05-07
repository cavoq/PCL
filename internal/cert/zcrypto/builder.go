// Package zcrypto provides zcrypto-based X.509 certificate parsing and node tree building.
package zcrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/ct"

	"github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/zcrypto"
)

type ZCryptoBuilder struct{}

func NewZCryptoBuilder() *ZCryptoBuilder {
	return &ZCryptoBuilder{}
}

func (b *ZCryptoBuilder) Build(cert *x509.Certificate) *node.Node {
	return buildCertificate(cert)
}

func BuildTree(cert *x509.Certificate) *node.Node {
	return NewZCryptoBuilder().Build(cert)
}

func buildCertificate(cert *x509.Certificate) *node.Node {
	root := node.New("certificate", nil)

	root.Children["version"] = node.New("version", cert.Version)

	if cert.SerialNumber != nil {
		serialNode := node.New("serialNumber", cert.SerialNumber.Bytes())
		serialNode.Children["value"] = node.New("value", cert.SerialNumber.String())
		root.Children["serialNumber"] = serialNode
	}

	root.Children["signatureAlgorithm"] = buildSignatureAlgorithm(cert)
	root.Children["tbsSignatureAlgorithm"] = buildTBSSignatureAlgorithm(cert)
	root.Children["issuer"] = zcrypto.BuildPkixName("issuer", cert.Issuer)
	root.Children["validity"] = buildValidity(cert)
	root.Children["subject"] = zcrypto.BuildPkixName("subject", cert.Subject)
	root.Children["subjectPublicKeyInfo"] = buildSubjectPublicKeyInfo(cert)

	if cert.IssuerUniqueId.BitLength > 0 {
		root.Children["issuerUniqueID"] = node.New("issuerUniqueID", cert.IssuerUniqueId.Bytes)
	}

	if cert.SubjectUniqueId.BitLength > 0 {
		root.Children["subjectUniqueID"] = node.New("subjectUniqueID", cert.SubjectUniqueId.Bytes)
	}

	if len(cert.Extensions) > 0 {
		root.Children["extensions"] = zcrypto.BuildExtensions(cert.Extensions)

		// Parse AIA extension with full ASN.1 structure
		for _, ext := range cert.Extensions {
			oidStr := ext.Id.String()
			if oidStr == "1.3.6.1.5.5.7.1.1" {
				aiaNode := ParseAIA(ext.Value)
				if extNode, ok := root.Children["extensions"].Children["authorityInfoAccess"]; ok {
					// Merge parsed AIA into extension node
					for k, v := range aiaNode.Children {
						extNode.Children[k] = v
					}
				}
			}
			if oidStr == "2.5.29.31" {
				crlDPNode := ParseCRLDP(ext.Value)
				if extNode, ok := root.Children["extensions"].Children["cRLDistributionPoints"]; ok {
					// Merge parsed CRL DP into extension node
					for k, v := range crlDPNode.Children {
						extNode.Children[k] = v
					}
				}
			}
			if oidStr == "2.5.29.32" {
				certPoliciesNode := ParseCertPolicies(ext.Value)
				if extNode, ok := root.Children["extensions"].Children["certificatePolicies"]; ok {
					// Merge parsed Certificate Policies into extension node
					for k, v := range certPoliciesNode.Children {
						extNode.Children[k] = v
					}
				}
			}
		}
	}

	root.Children["keyUsage"] = buildKeyUsage(cert.KeyUsage)

	if len(cert.ExtKeyUsage) > 0 {
		root.Children["extKeyUsage"] = buildExtKeyUsage(cert.ExtKeyUsage)
	}

	if cert.BasicConstraintsValid {
		root.Children["basicConstraints"] = buildBasicConstraints(cert)
	}

	if len(cert.SubjectKeyId) > 0 {
		root.Children["subjectKeyIdentifier"] = node.New("subjectKeyIdentifier", cert.SubjectKeyId)
	}

	if len(cert.AuthorityKeyId) > 0 {
		root.Children["authorityKeyIdentifier"] = node.New("authorityKeyIdentifier", cert.AuthorityKeyId)
	}

	if hasSAN(cert) {
		root.Children["subjectAltName"] = buildSubjectAltName(cert)
	}

	// Add Issuer Alt Name (IAN)
	if hasIAN(cert) {
		root.Children["issuerAltName"] = buildIssuerAltName(cert)
	}

	// Add Name Constraints (for CA certificates)
	if hasNameConstraints(cert) {
		root.Children["nameConstraints"] = buildNameConstraints(cert)
	}

	// Add CABF Organization Identifier (for EV certificates)
	if cert.CABFOrganizationIdentifier != nil {
		root.Children["cabfOrganizationIdentifier"] = buildCABFOrganizationID(cert)
	}

	if len(cert.Signature) > 0 {
		root.Children["signatureValue"] = node.New("signatureValue", cert.Signature)
	}

	// Add OCSP URL from AIA extension
	if len(cert.OCSPServer) > 0 {
		root.Children["ocspURL"] = node.New("ocspURL", cert.OCSPServer[0])
	}

	// Add CA Issuers URL from AIA extension
	if len(cert.IssuingCertificateURL) > 0 {
		root.Children["caIssuersURL"] = node.New("caIssuersURL", cert.IssuingCertificateURL[0])
	}

	// Add CRL Distribution Points
	if len(cert.CRLDistributionPoints) > 0 {
		crlDPNode := node.New("cRLDistributionPoints", nil)
		for i, uri := range cert.CRLDistributionPoints {
			crlDPNode.Children[fmt.Sprintf("%d", i)] = node.New(fmt.Sprintf("%d", i), uri)
		}
		root.Children["cRLDistributionPoints"] = crlDPNode
	}

	// Add Signed Certificate Timestamps (SCT) from CT extension
	if len(cert.SignedCertificateTimestampList) > 0 {
		sctNode := node.New("signedCertificateTimestamps", nil)
		for i, sct := range cert.SignedCertificateTimestampList {
			sctNode.Children[fmt.Sprintf("%d", i)] = buildSCT(sct, i)
		}
		root.Children["signedCertificateTimestamps"] = sctNode
	}

	// Add Certificate Policies
	if len(cert.PolicyIdentifiers) > 0 {
		policiesNode := node.New("certificatePolicies", nil)
		for i, oid := range cert.PolicyIdentifiers {
			policyNode := node.New(fmt.Sprintf("%d", i), nil)
			policyNode.Children["oid"] = node.New("oid", oid.String())
			policiesNode.Children[oid.String()] = policyNode
			// Add friendly name for known policy OIDs
			friendlyName := policyFriendlyName(oid.String())
			if friendlyName != "" {
				policiesNode.Children[friendlyName] = policyNode
			}
		}
		root.Children["certificatePolicies"] = policiesNode
	}

	return root
}

func buildSignatureAlgorithm(cert *x509.Certificate) *node.Node {
	n := node.New("signatureAlgorithm", nil)
	n.Children["algorithm"] = node.New("algorithm", cert.SignatureAlgorithm.String())
	if len(cert.SignatureAlgorithmOID) > 0 {
		n.Children["oid"] = node.New("oid", cert.SignatureAlgorithmOID.String())
	}
	params := ParseCertSignatureAlgorithmParams(cert.Raw)
	// Add raw DER bytes for byte-for-byte encoding validation (Mozilla requirements)
	if len(params.RawDER) > 0 {
		n.Children["rawDER"] = node.New("rawDER", params.RawDER)
	}
	paramsNode := buildAlgorithmIDParams(params)
	if paramsNode != nil {
		n.Children["parameters"] = paramsNode
	}
	return n
}

func buildTBSSignatureAlgorithm(cert *x509.Certificate) *node.Node {
	n := node.New("tbsSignatureAlgorithm", nil)
	n.Children["algorithm"] = node.New("algorithm", cert.SignatureAlgorithm.String())
	if len(cert.SignatureAlgorithmOID) > 0 {
		n.Children["oid"] = node.New("oid", cert.SignatureAlgorithmOID.String())
	}
	params := ParseTBSCertSignatureParams(cert.RawTBSCertificate)
	// Add raw DER bytes for byte-for-byte encoding validation (Mozilla requirements)
	if len(params.RawDER) > 0 {
		n.Children["rawDER"] = node.New("rawDER", params.RawDER)
	}
	paramsNode := buildAlgorithmIDParams(params)
	if paramsNode != nil {
		n.Children["parameters"] = paramsNode
	}
	return n
}

func buildAlgorithmIDParams(params asn1.ParamsState) *node.Node {
	// If parameters are absent, do NOT create a node.
	// This allows the `absent` operator to work correctly.
	if params.IsAbsent {
		return nil
	}

	// If parameters are NULL, create node with null=true.
	// This allows the `isNull` operator to work correctly.
	n := node.New("parameters", nil)
	n.Children["null"] = node.New("null", params.IsNull)

	// For ECDSA, the NamedCurve is the curve OID (e.g., secp256r1, secp384r1)
	if params.NamedCurve != "" {
		n.Children["namedCurve"] = node.New("namedCurve", params.NamedCurve)
	}

	if params.PSS != nil {
		n.Children["pss"] = buildPSSParams(params.PSS)
	}

	if params.OAEP != nil {
		n.Children["oaep"] = buildOAEPParams(params.OAEP)
	}

	return n
}

func buildPSSParams(pss *asn1.PSSParams) *node.Node {
	n := node.New("pss", nil)

	n.Children["hashAlgorithm"] = buildNestedAlgorithmID(pss.HashAlgorithm)
	n.Children["hashAlgorithmSet"] = node.New("hashAlgorithmSet", pss.HashAlgorithmSet)
	n.Children["maskGenAlgorithm"] = buildNestedAlgorithmID(pss.MaskGenAlgorithm)
	n.Children["maskGenAlgorithmSet"] = node.New("maskGenAlgorithmSet", pss.MaskGenAlgorithmSet)
	n.Children["saltLength"] = node.New("saltLength", pss.SaltLength)
	n.Children["saltLengthSet"] = node.New("saltLengthSet", pss.SaltLengthSet)
	n.Children["trailerField"] = node.New("trailerField", pss.TrailerField)
	n.Children["trailerFieldSet"] = node.New("trailerFieldSet", pss.TrailerFieldSet)

	return n
}

func buildOAEPParams(oaep *asn1.OAEPParams) *node.Node {
	n := node.New("oaep", nil)

	n.Children["hashAlgorithm"] = buildNestedAlgorithmID(oaep.HashAlgorithm)
	n.Children["hashAlgorithmSet"] = node.New("hashAlgorithmSet", oaep.HashAlgorithmSet)
	n.Children["maskGenAlgorithm"] = buildNestedAlgorithmID(oaep.MaskGenAlgorithm)
	n.Children["maskGenAlgorithmSet"] = node.New("maskGenAlgorithmSet", oaep.MaskGenAlgorithmSet)
	n.Children["pSourceAlgorithm"] = buildNestedAlgorithmID(oaep.PSourceAlgorithm)
	n.Children["pSourceAlgorithmSet"] = node.New("pSourceAlgorithmSet", oaep.PSourceAlgorithmSet)

	return n
}

func buildNestedAlgorithmID(algo asn1.AlgorithmIdentifier) *node.Node {
	n := node.New("algorithm", nil)
	n.Children["oid"] = node.New("oid", algo.OID)
	params := buildAlgorithmIDParams(algo.Params)
	if params != nil {
		n.Children["parameters"] = params
	}
	return n
}

func buildValidity(cert *x509.Certificate) *node.Node {
	n := node.New("validity", nil)

	notBeforeNode := node.New("notBefore", cert.NotBefore)
	notAfterNode := node.New("notAfter", cert.NotAfter)

	// Parse time encoding info from TBSCertificate
	if len(cert.RawTBSCertificate) > 0 {
		encodingInfo, err := ParseValidityEncoding(cert.RawTBSCertificate)
		if err == nil && encodingInfo != nil {
			if encodingInfo.NotBefore != nil {
				notBeforeNode.Children["encoding"] = node.New("encoding", encodingInfo.NotBefore.Tag)
				notBeforeNode.Children["format"] = node.New("format", encodingInfo.NotBefore.RawString)
				notBeforeNode.Children["isUTC"] = node.New("isUTC", encodingInfo.NotBefore.IsUTC)
				notBeforeNode.Children["hasSeconds"] = node.New("hasSeconds", encodingInfo.NotBefore.HasSeconds)
				notBeforeNode.Children["hasZulu"] = node.New("hasZulu", encodingInfo.NotBefore.HasZulu)
			}
			if encodingInfo.NotAfter != nil {
				notAfterNode.Children["encoding"] = node.New("encoding", encodingInfo.NotAfter.Tag)
				notAfterNode.Children["format"] = node.New("format", encodingInfo.NotAfter.RawString)
				notAfterNode.Children["isUTC"] = node.New("isUTC", encodingInfo.NotAfter.IsUTC)
				notAfterNode.Children["hasSeconds"] = node.New("hasSeconds", encodingInfo.NotAfter.HasSeconds)
				notAfterNode.Children["hasZulu"] = node.New("hasZulu", encodingInfo.NotAfter.HasZulu)
			}
		}
	}

	n.Children["notBefore"] = notBeforeNode
	n.Children["notAfter"] = notAfterNode
	return n
}

func buildSubjectPublicKeyInfo(cert *x509.Certificate) *node.Node {
	n := node.New("subjectPublicKeyInfo", nil)

	algo := node.New("algorithm", nil)
	algo.Children["algorithm"] = node.New("algorithm", cert.PublicKeyAlgorithm.String())
	if len(cert.PublicKeyAlgorithmOID) > 0 {
		algo.Children["oid"] = node.New("oid", cert.PublicKeyAlgorithmOID.String())
	}
	params := ParseSubjectPublicKeyInfoParams(cert.RawSubjectPublicKeyInfo)
	// Add raw DER bytes for byte-for-byte encoding validation (Mozilla requirements)
	if len(params.RawDER) > 0 {
		algo.Children["rawDER"] = node.New("rawDER", params.RawDER)
	}
	paramsNode := buildAlgorithmIDParams(params)
	if paramsNode != nil {
		algo.Children["parameters"] = paramsNode
	}
	n.Children["algorithm"] = algo

	if cert.PublicKey != nil {
		switch key := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			n.Children["publicKey"] = buildRSAKey(key)
		case *ecdsa.PublicKey:
			n.Children["publicKey"] = buildECDSAKey(key)
		case ed25519.PublicKey:
			n.Children["publicKey"] = buildEd25519Key(key)
		default:
			n.Children["publicKey"] = node.New("publicKey", cert.PublicKey)
		}
	}

	return n
}

func buildKeyUsage(ku x509.KeyUsage) *node.Node {
	n := node.New("keyUsage", int(ku))

	if ku&x509.KeyUsageDigitalSignature != 0 {
		n.Children["digitalSignature"] = node.New("digitalSignature", true)
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		// Both names for the same bit: contentCommitment (RFC name) and nonRepudiation (common name)
		n.Children["contentCommitment"] = node.New("contentCommitment", true)
		n.Children["nonRepudiation"] = node.New("nonRepudiation", true)
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		n.Children["keyEncipherment"] = node.New("keyEncipherment", true)
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		n.Children["dataEncipherment"] = node.New("dataEncipherment", true)
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		n.Children["keyAgreement"] = node.New("keyAgreement", true)
	}
	if ku&x509.KeyUsageCertSign != 0 {
		n.Children["keyCertSign"] = node.New("keyCertSign", true)
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		n.Children["cRLSign"] = node.New("cRLSign", true)
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		n.Children["encipherOnly"] = node.New("encipherOnly", true)
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		n.Children["decipherOnly"] = node.New("decipherOnly", true)
	}

	return n
}

func buildExtKeyUsage(ekus []x509.ExtKeyUsage) *node.Node {
	n := node.New("extKeyUsage", nil)

	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			n.Children["any"] = node.New("any", true)
		case x509.ExtKeyUsageServerAuth:
			n.Children["serverAuth"] = node.New("serverAuth", true)
		case x509.ExtKeyUsageClientAuth:
			n.Children["clientAuth"] = node.New("clientAuth", true)
		case x509.ExtKeyUsageCodeSigning:
			n.Children["codeSigning"] = node.New("codeSigning", true)
		case x509.ExtKeyUsageEmailProtection:
			n.Children["emailProtection"] = node.New("emailProtection", true)
		case x509.ExtKeyUsageTimeStamping:
			n.Children["timeStamping"] = node.New("timeStamping", true)
		case x509.ExtKeyUsageOcspSigning:
			n.Children["ocspSigning"] = node.New("ocspSigning", true)
		}
	}

	return n
}

func buildBasicConstraints(cert *x509.Certificate) *node.Node {
	n := node.New("basicConstraints", nil)
	n.Children["cA"] = node.New("cA", cert.IsCA)
	if cert.MaxPathLen >= 0 || cert.MaxPathLenZero {
		n.Children["pathLenConstraint"] = node.New("pathLenConstraint", cert.MaxPathLen)
	}
	return n
}

func hasSAN(cert *x509.Certificate) bool {
	return len(cert.DNSNames) > 0 ||
		len(cert.EmailAddresses) > 0 ||
		len(cert.IPAddresses) > 0 ||
		len(cert.URIs) > 0
}

func buildSubjectAltName(cert *x509.Certificate) *node.Node {
	n := node.New("subjectAltName", nil)

	if len(cert.DNSNames) > 0 {
		dnsNode := node.New("dNSName", nil)
		for i, dns := range cert.DNSNames {
			dnsNode.Children[string(rune('0'+i))] = node.New(string(rune('0'+i)), dns)
		}
		n.Children["dNSName"] = dnsNode
	}

	if len(cert.EmailAddresses) > 0 {
		emailNode := node.New("rfc822Name", nil)
		for i, email := range cert.EmailAddresses {
			emailNode.Children[string(rune('0'+i))] = node.New(string(rune('0'+i)), email)
		}
		n.Children["rfc822Name"] = emailNode
	}

	if len(cert.IPAddresses) > 0 {
		ipNode := node.New("iPAddress", nil)
		for i, ip := range cert.IPAddresses {
			ipNode.Children[string(rune('0'+i))] = node.New(string(rune('0'+i)), ip.String())
		}
		n.Children["iPAddress"] = ipNode
	}

	if len(cert.URIs) > 0 {
		uriNode := node.New("uniformResourceIdentifier", nil)
		for i, uri := range cert.URIs {
			uriNode.Children[string(rune('0'+i))] = node.New(string(rune('0'+i)), uri)
		}
		n.Children["uniformResourceIdentifier"] = uriNode
	}

	return n
}

func hasIAN(cert *x509.Certificate) bool {
	return len(cert.IANDNSNames) > 0 ||
		len(cert.IANEmailAddresses) > 0 ||
		len(cert.IANIPAddresses) > 0 ||
		len(cert.IANURIs) > 0
}

func buildIssuerAltName(cert *x509.Certificate) *node.Node {
	n := node.New("issuerAltName", nil)

	if len(cert.IANDNSNames) > 0 {
		dnsNode := node.New("dNSName", nil)
		for i, dns := range cert.IANDNSNames {
			dnsNode.Children[string(rune('0'+i))] = node.New(string(rune('0'+i)), dns)
		}
		n.Children["dNSName"] = dnsNode
	}

	if len(cert.IANEmailAddresses) > 0 {
		emailNode := node.New("rfc822Name", nil)
		for i, email := range cert.IANEmailAddresses {
			emailNode.Children[string(rune('0'+i))] = node.New(string(rune('0'+i)), email)
		}
		n.Children["rfc822Name"] = emailNode
	}

	if len(cert.IANIPAddresses) > 0 {
		ipNode := node.New("iPAddress", nil)
		for i, ip := range cert.IANIPAddresses {
			ipNode.Children[string(rune('0'+i))] = node.New(string(rune('0'+i)), ip.String())
		}
		n.Children["iPAddress"] = ipNode
	}

	if len(cert.IANURIs) > 0 {
		uriNode := node.New("uniformResourceIdentifier", nil)
		for i, uri := range cert.IANURIs {
			uriNode.Children[string(rune('0'+i))] = node.New(string(rune('0'+i)), uri)
		}
		n.Children["uniformResourceIdentifier"] = uriNode
	}

	return n
}

func buildRSAKey(key *rsa.PublicKey) *node.Node {
	n := node.New("publicKey", nil)
	n.Children["keySize"] = node.New("keySize", key.N.BitLen())
	n.Children["exponent"] = node.New("exponent", key.E)
	return n
}

func buildECDSAKey(key *ecdsa.PublicKey) *node.Node {
	n := node.New("publicKey", nil)
	n.Children["keySize"] = node.New("keySize", key.Curve.Params().BitSize)
	n.Children["curve"] = node.New("curve", key.Curve.Params().Name)
	return n
}

func buildEd25519Key(key ed25519.PublicKey) *node.Node {
	n := node.New("publicKey", nil)
	n.Children["keySize"] = node.New("keySize", len(key)*8) // Ed25519 key size in bits
	return n
}

func buildSCT(sct interface{}, index int) *node.Node {
	n := node.New(fmt.Sprintf("%d", index), nil)
	n.Children["present"] = node.New("present", true)

	// Try to cast to ct.SignedCertificateTimestamp
	ctSCT, ok := sct.(*ct.SignedCertificateTimestamp)
	if !ok {
		// Fallback for unknown SCT type
		return n
	}

	// Version (V1=0 per RFC 6962/9162)
	n.Children["version"] = node.New("version", int(ctSCT.SCTVersion))
	n.Children["versionString"] = node.New("versionString", ctSCT.SCTVersion.String())

	// LogID - 32 bytes SHA-256 hash of log's public key
	if len(ctSCT.LogID) == 32 {
		n.Children["logID"] = node.New("logID", ctSCT.LogID[:])
		n.Children["logIDHex"] = node.New("logIDHex", hex.EncodeToString(ctSCT.LogID[:]))
	}

	// Timestamp - milliseconds since Unix epoch
	n.Children["timestamp"] = node.New("timestamp", ctSCT.Timestamp)
	// Convert to time.Time for easier validation
	timestampTime := time.Unix(0, int64(ctSCT.Timestamp)*int64(time.Millisecond))
	n.Children["timestampTime"] = node.New("timestampTime", timestampTime)

	// Extensions - optional
	if len(ctSCT.Extensions) > 0 {
		n.Children["extensions"] = node.New("extensions", ctSCT.Extensions)
		n.Children["extensionsLen"] = node.New("extensionsLen", len(ctSCT.Extensions))
	} else {
		n.Children["extensionsLen"] = node.New("extensionsLen", 0)
	}

	// Signature - DigitallySigned structure
	sigNode := node.New("signature", nil)
	sigNode.Children["hashAlgorithm"] = node.New("hashAlgorithm", ctSCT.Signature.HashAlgorithm.String())
	sigNode.Children["hashAlgorithmValue"] = node.New("hashAlgorithmValue", int(ctSCT.Signature.HashAlgorithm))
	sigNode.Children["signatureAlgorithm"] = node.New("signatureAlgorithm", ctSCT.Signature.SignatureAlgorithm.String())
	sigNode.Children["signatureAlgorithmValue"] = node.New("signatureAlgorithmValue", int(ctSCT.Signature.SignatureAlgorithm))
	sigNode.Children["signatureValue"] = node.New("signatureValue", ctSCT.Signature.Signature)
	sigNode.Children["signatureValueHex"] = node.New("signatureValueHex", hex.EncodeToString(ctSCT.Signature.Signature))
	n.Children["signature"] = sigNode

	// Combined signature algorithm string (e.g., "SHA256-ECDSA")
	sigAlgStr := fmt.Sprintf("%s-%s", ctSCT.Signature.HashAlgorithm.String(), ctSCT.Signature.SignatureAlgorithm.String())
	n.Children["signatureAlgorithmString"] = node.New("signatureAlgorithmString", sigAlgStr)

	return n
}

func hasNameConstraints(cert *x509.Certificate) bool {
	return len(cert.PermittedDNSNames) > 0 ||
		len(cert.ExcludedDNSNames) > 0 ||
		len(cert.PermittedEmailAddresses) > 0 ||
		len(cert.ExcludedEmailAddresses) > 0 ||
		len(cert.PermittedURIs) > 0 ||
		len(cert.ExcludedURIs) > 0 ||
		len(cert.PermittedIPAddresses) > 0 ||
		len(cert.ExcludedIPAddresses) > 0 ||
		len(cert.PermittedDirectoryNames) > 0 ||
		len(cert.ExcludedDirectoryNames) > 0
}

func buildNameConstraints(cert *x509.Certificate) *node.Node {
	n := node.New("nameConstraints", nil)

	// Critical flag
	n.Children["critical"] = node.New("critical", cert.NameConstraintsCritical)

	// Permitted subtrees
	if len(cert.PermittedDNSNames) > 0 ||
		len(cert.PermittedEmailAddresses) > 0 ||
		len(cert.PermittedURIs) > 0 ||
		len(cert.PermittedIPAddresses) > 0 ||
		len(cert.PermittedDirectoryNames) > 0 {
		permittedNode := node.New("permittedSubtrees", nil)
		buildGeneralSubtrees(permittedNode, "dNSName", cert.PermittedDNSNames)
		buildGeneralSubtrees(permittedNode, "rfc822Name", cert.PermittedEmailAddresses)
		buildGeneralSubtrees(permittedNode, "uniformResourceIdentifier", cert.PermittedURIs)
		buildGeneralSubtreeIPs(permittedNode, "iPAddress", cert.PermittedIPAddresses)
		buildGeneralSubtreeNames(permittedNode, "directoryName", cert.PermittedDirectoryNames)
		n.Children["permittedSubtrees"] = permittedNode
	}

	// Excluded subtrees
	if len(cert.ExcludedDNSNames) > 0 ||
		len(cert.ExcludedEmailAddresses) > 0 ||
		len(cert.ExcludedURIs) > 0 ||
		len(cert.ExcludedIPAddresses) > 0 ||
		len(cert.ExcludedDirectoryNames) > 0 {
		excludedNode := node.New("excludedSubtrees", nil)
		buildGeneralSubtrees(excludedNode, "dNSName", cert.ExcludedDNSNames)
		buildGeneralSubtrees(excludedNode, "rfc822Name", cert.ExcludedEmailAddresses)
		buildGeneralSubtrees(excludedNode, "uniformResourceIdentifier", cert.ExcludedURIs)
		buildGeneralSubtreeIPs(excludedNode, "iPAddress", cert.ExcludedIPAddresses)
		buildGeneralSubtreeNames(excludedNode, "directoryName", cert.ExcludedDirectoryNames)
		n.Children["excludedSubtrees"] = excludedNode
	}

	return n
}

func buildGeneralSubtrees(parent *node.Node, name string, subtrees []x509.GeneralSubtreeString) {
	if len(subtrees) == 0 {
		return
	}
	subtreeNode := node.New(name, nil)
	for i, subtree := range subtrees {
		child := node.New(fmt.Sprintf("%d", i), nil)
		child.Children["value"] = node.New("value", subtree.Data)
		if subtree.Min > 0 {
			child.Children["min"] = node.New("min", subtree.Min)
		}
		if subtree.Max > 0 {
			child.Children["max"] = node.New("max", subtree.Max)
		}
		subtreeNode.Children[fmt.Sprintf("%d", i)] = child
	}
	parent.Children[name] = subtreeNode
}

func buildGeneralSubtreeIPs(parent *node.Node, name string, subtrees []x509.GeneralSubtreeIP) {
	if len(subtrees) == 0 {
		return
	}
	subtreeNode := node.New(name, nil)
	for i, subtree := range subtrees {
		child := node.New(fmt.Sprintf("%d", i), nil)
		child.Children["value"] = node.New("value", subtree.Data.String())
		if subtree.Min > 0 {
			child.Children["min"] = node.New("min", subtree.Min)
		}
		if subtree.Max > 0 {
			child.Children["max"] = node.New("max", subtree.Max)
		}
		subtreeNode.Children[fmt.Sprintf("%d", i)] = child
	}
	parent.Children[name] = subtreeNode
}

func buildGeneralSubtreeNames(parent *node.Node, name string, subtrees []x509.GeneralSubtreeName) {
	if len(subtrees) == 0 {
		return
	}
	subtreeNode := node.New(name, nil)
	for i, subtree := range subtrees {
		child := node.New(fmt.Sprintf("%d", i), nil)
		child.Children["value"] = zcrypto.BuildPkixName("value", subtree.Data)
		if subtree.Min > 0 {
			child.Children["min"] = node.New("min", subtree.Min)
		}
		if subtree.Max > 0 {
			child.Children["max"] = node.New("max", subtree.Max)
		}
		subtreeNode.Children[fmt.Sprintf("%d", i)] = child
	}
	parent.Children[name] = subtreeNode
}

func buildCABFOrganizationID(cert *x509.Certificate) *node.Node {
	n := node.New("cabfOrganizationIdentifier", nil)

	orgID := cert.CABFOrganizationIdentifier
	if orgID == nil {
		return n
	}

	if orgID.Scheme != "" {
		n.Children["scheme"] = node.New("scheme", orgID.Scheme)
	}
	if orgID.Country != "" {
		n.Children["country"] = node.New("country", orgID.Country)
	}
	if orgID.State != "" {
		n.Children["state"] = node.New("state", orgID.State)
	}
	if orgID.Reference != "" {
		n.Children["reference"] = node.New("reference", orgID.Reference)
	}

	return n
}