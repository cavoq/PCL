// Package zcrypto provides zcrypto-based X.509 certificate parsing and node tree building.
package zcrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/ct"
	"github.com/zmap/zcrypto/x509/pkix"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/zcrypto"
)

type ZCryptoBuilder struct{}

type extensionNodeParser func([]byte) (*node.Node, error)

var certificateExtensionParsers = map[string]extensionNodeParser{
	oid.AuthorityInfoAccess:   ParseAIAStrict,
	oid.CRLDistributionPoints: ParseCRLDPStrict,
	oid.CertificatePolicies:   ParseCertPoliciesStrict,
}

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
	root.Children["subjectEmpty"] = node.New("subjectEmpty", len(cert.Subject.Names) == 0)
	root.Children["subjectPublicKeyInfo"] = buildSubjectPublicKeyInfo(cert)

	if cert.IssuerUniqueId.BitLength > 0 {
		root.Children["issuerUniqueID"] = node.New("issuerUniqueID", cert.IssuerUniqueId.Bytes)
	}

	if cert.SubjectUniqueId.BitLength > 0 {
		root.Children["subjectUniqueID"] = node.New("subjectUniqueID", cert.SubjectUniqueId.Bytes)
	}

	if len(cert.Extensions) > 0 {
		root.Children["extensions"] = zcrypto.BuildExtensions(cert.Extensions)
		extensionsNode := root.Children["extensions"]
		for _, ext := range cert.Extensions {
			oidStr := ext.Id.String()
			parser, supported := certificateExtensionParsers[oidStr]
			if !supported {
				continue
			}
			extNode := extensionsNode.Children[oidStr]
			parsed, err := parser(ext.Value)
			if err != nil {
				extNode.Children["malformed"] = node.New("malformed", true)
				continue
			}
			for name, child := range parsed.Children {
				extNode.Children[name] = child
			}
		}
	}

	if hasExtension(cert.Extensions, oid.KeyUsage) {
		root.Children["keyUsage"] = buildKeyUsage(cert.KeyUsage)
	}

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

	if hasExtension(cert.Extensions, oid.SubjectAlternativeName) {
		root.Children["subjectAltName"] = buildSubjectAltName(cert)
	}

	// Add Issuer Alt Name (IAN)
	if hasExtension(cert.Extensions, oid.IssuerAlternativeName) {
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
		for i, policyID := range cert.PolicyIdentifiers {
			policyOID := policyID.String()
			policyNode := node.New(fmt.Sprintf("%d", i), nil)
			policyNode.Children["oid"] = node.New("oid", policyOID)
			policiesNode.Children[policyOID] = policyNode
			// Add friendly name for known policy OIDs
			friendlyName, known := oid.CertificatePolicyName(policyOID)
			if known {
				policiesNode.Children[friendlyName] = policyNode
			}
		}
		root.Children["certificatePolicies"] = policiesNode
	}

	return root
}

func buildSignatureAlgorithm(cert *x509.Certificate) *node.Node {
	params := internalasn1.ParseSignedObjectAlgorithmParams(cert.Raw)
	return zcrypto.BuildAlgorithmIdentifier("signatureAlgorithm", cert.SignatureAlgorithm.String(), params)
}

func buildTBSSignatureAlgorithm(cert *x509.Certificate) *node.Node {
	params := parseTBSCertSignatureParams(cert.RawTBSCertificate)
	return zcrypto.BuildAlgorithmIdentifier("tbsSignatureAlgorithm", cert.SignatureAlgorithm.String(), params)
}

func buildValidity(cert *x509.Certificate) *node.Node {
	n := node.New("validity", nil)

	notBeforeNode := node.New("notBefore", cert.NotBefore)
	notAfterNode := node.New("notAfter", cert.NotAfter)

	if len(cert.RawTBSCertificate) > 0 {
		encoding, err := parseValidityEncoding(cert.RawTBSCertificate)
		if err == nil {
			addTimeEncoding(notBeforeNode, encoding.NotBefore)
			addTimeEncoding(notAfterNode, encoding.NotAfter)
		}
	}

	n.Children["notBefore"] = notBeforeNode
	n.Children["notAfter"] = notAfterNode
	return n
}

func addTimeEncoding(target *node.Node, encoding internalasn1.TimeFormatInfo) {
	target.Children["encoding"] = node.New("encoding", encoding.Tag)
	target.Children["format"] = node.New("format", encoding.RawString)
	target.Children["isUTC"] = node.New("isUTC", encoding.IsUTC)
	target.Children["hasSeconds"] = node.New("hasSeconds", encoding.HasSeconds)
	target.Children["hasZulu"] = node.New("hasZulu", encoding.HasZulu)
}

func buildSubjectPublicKeyInfo(cert *x509.Certificate) *node.Node {
	n := node.New("subjectPublicKeyInfo", nil)

	params := parseSubjectPublicKeyInfoParams(cert.RawSubjectPublicKeyInfo)
	algo := zcrypto.BuildAlgorithmIdentifier("algorithm", cert.PublicKeyAlgorithm.String(), params)
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
	n.Children["digitalSignature"] = node.New("digitalSignature", ku&x509.KeyUsageDigitalSignature != 0)
	contentCommitment := ku&x509.KeyUsageContentCommitment != 0
	n.Children["contentCommitment"] = node.New("contentCommitment", contentCommitment)
	n.Children["nonRepudiation"] = node.New("nonRepudiation", contentCommitment)
	n.Children["keyEncipherment"] = node.New("keyEncipherment", ku&x509.KeyUsageKeyEncipherment != 0)
	n.Children["dataEncipherment"] = node.New("dataEncipherment", ku&x509.KeyUsageDataEncipherment != 0)
	n.Children["keyAgreement"] = node.New("keyAgreement", ku&x509.KeyUsageKeyAgreement != 0)
	n.Children["keyCertSign"] = node.New("keyCertSign", ku&x509.KeyUsageCertSign != 0)
	n.Children["cRLSign"] = node.New("cRLSign", ku&x509.KeyUsageCRLSign != 0)
	n.Children["encipherOnly"] = node.New("encipherOnly", ku&x509.KeyUsageEncipherOnly != 0)
	n.Children["decipherOnly"] = node.New("decipherOnly", ku&x509.KeyUsageDecipherOnly != 0)

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

func hasExtension(extensions []pkix.Extension, targetOID string) bool {
	_, ok := findExtension(extensions, targetOID)
	return ok
}

func findExtension(extensions []pkix.Extension, targetOID string) (pkix.Extension, bool) {
	for _, extension := range extensions {
		if extension.Id.String() == targetOID {
			return extension, true
		}
	}
	return pkix.Extension{}, false
}

func buildSubjectAltName(cert *x509.Certificate) *node.Node {
	n := buildGeneralNames("subjectAltName", generalNames{
		otherNames:     cert.OtherNames,
		dnsNames:       cert.DNSNames,
		emailAddresses: cert.EmailAddresses,
		directoryNames: cert.DirectoryNames,
		ediPartyNames:  cert.EDIPartyNames,
		uris:           cert.URIs,
		ipAddresses:    cert.IPAddresses,
		registeredIDs:  cert.RegisteredIDs,
	})
	addRawGeneralNamesInfo(n, cert.Extensions, oid.SubjectAlternativeName)
	return n
}

func buildIssuerAltName(cert *x509.Certificate) *node.Node {
	n := buildGeneralNames("issuerAltName", generalNames{
		otherNames:     cert.IANOtherNames,
		dnsNames:       cert.IANDNSNames,
		emailAddresses: cert.IANEmailAddresses,
		directoryNames: cert.IANDirectoryNames,
		ediPartyNames:  cert.IANEDIPartyNames,
		uris:           cert.IANURIs,
		ipAddresses:    cert.IANIPAddresses,
		registeredIDs:  cert.IANRegisteredIDs,
	})
	addRawGeneralNamesInfo(n, cert.Extensions, oid.IssuerAlternativeName)
	return n
}

type generalNames struct {
	otherNames     []pkix.OtherName
	dnsNames       []string
	emailAddresses []string
	directoryNames []pkix.Name
	ediPartyNames  []pkix.EDIPartyName
	uris           []string
	ipAddresses    []net.IP
	registeredIDs  []zasn1.ObjectIdentifier
}

func buildGeneralNames(name string, names generalNames) *node.Node {
	n := node.New(name, nil)
	addGeneralNameStrings(n, "dNSName", names.dnsNames)
	addGeneralNameStrings(n, "rfc822Name", names.emailAddresses)
	addGeneralNameStrings(n, "uniformResourceIdentifier", names.uris)

	if len(names.ipAddresses) > 0 {
		values := node.New("iPAddress", nil)
		for i, value := range names.ipAddresses {
			index := strconv.Itoa(i)
			values.Children[index] = node.New(index, value.String())
		}
		n.Children["iPAddress"] = values
	}

	if len(names.otherNames) > 0 {
		values := node.New("otherName", nil)
		for i, value := range names.otherNames {
			index := strconv.Itoa(i)
			entry := node.New(index, value.Value.FullBytes)
			entry.Children["typeID"] = node.New("typeID", value.TypeID.String())
			values.Children[index] = entry
		}
		n.Children["otherName"] = values
	}

	if len(names.directoryNames) > 0 {
		values := node.New("directoryName", nil)
		for i, value := range names.directoryNames {
			index := strconv.Itoa(i)
			values.Children[index] = zcrypto.BuildPkixName(index, value)
		}
		n.Children["directoryName"] = values
	}

	if len(names.ediPartyNames) > 0 {
		values := node.New("ediPartyName", nil)
		for i, value := range names.ediPartyNames {
			index := strconv.Itoa(i)
			entry := node.New(index, nil)
			if value.NameAssigner != "" {
				entry.Children["nameAssigner"] = node.New("nameAssigner", value.NameAssigner)
			}
			entry.Children["partyName"] = node.New("partyName", value.PartyName)
			values.Children[index] = entry
		}
		n.Children["ediPartyName"] = values
	}

	if len(names.registeredIDs) > 0 {
		values := node.New("registeredID", nil)
		for i, value := range names.registeredIDs {
			index := strconv.Itoa(i)
			values.Children[index] = node.New(index, value.String())
		}
		n.Children["registeredID"] = values
	}

	return n
}

func addGeneralNameStrings(parent *node.Node, name string, names []string) {
	if len(names) == 0 {
		return
	}
	values := node.New(name, nil)
	for i, value := range names {
		index := strconv.Itoa(i)
		values.Children[index] = node.New(index, value)
	}
	parent.Children[name] = values
}

func addRawGeneralNamesInfo(parent *node.Node, extensions []pkix.Extension, targetOID string) {
	extension, ok := findExtension(extensions, targetOID)
	if !ok {
		return
	}
	info, err := parseGeneralNamesInfo(extension.Value)
	if err != nil {
		return
	}
	parent.Value = info.Count
	if len(info.X400Addresses) > 0 {
		values := node.New("x400Address", nil)
		for i, value := range info.X400Addresses {
			index := strconv.Itoa(i)
			values.Children[index] = node.New(index, value)
		}
		parent.Children["x400Address"] = values
	}
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
