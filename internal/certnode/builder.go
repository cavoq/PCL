// Package certnode projects X.509 certificates into node trees. Strict
// extension decoding lives in package x509ext.
package certnode

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/zmap/zcrypto/dsa"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/ct"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/cavoq/PCL/internal/x509node"
)

type ZCryptoBuilder struct{}

type extensionNodeParser func([]byte) (*node.Node, error)

var certificateExtensionParsers = map[string]extensionNodeParser{
	oid.AuthorityInfoAccess:   ParseAIAStrict,
	oid.KeyUsage:              ParseKeyUsageStrict,
	oid.BasicConstraints:      ParseBasicConstraintsStrict,
	oid.NameConstraints:       ParseNameConstraintsStrict,
	oid.CRLDistributionPoints: ParseCRLDPStrict,
	oid.FreshestCRL:           ParseFreshestCRLStrict,
	oid.CertificatePolicies:   ParseCertPoliciesStrict,
	oid.PolicyMappings:        ParsePolicyMappingsStrict,
	oid.PolicyConstraints:     ParsePolicyConstraintsStrict,
	oid.ExtendedKeyUsage:      ParseExtKeyUsageStrict,
	oid.InhibitAnyPolicy:      ParseInhibitAnyPolicyStrict,
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
	metadata := projectTBSCertificateMetadata(root, cert.RawTBSCertificate)
	extensions := x509ext.NewExtensionIndex(cert.Extensions)

	root.Children["version"] = node.New("version", cert.Version)
	setChild(root, "serialNumber", buildSerialNumber(cert, metadata))

	root.Children["signatureAlgorithm"] = buildSignatureAlgorithm(cert)
	root.Children["tbsSignatureAlgorithm"] = buildTBSSignatureAlgorithm(cert)
	root.Children["issuer"] = x509node.BuildName("issuer", cert.RawIssuer, cert.Issuer)
	root.Children["validity"] = buildValidity(cert, metadata)
	root.Children["subject"] = x509node.BuildName("subject", cert.RawSubject, cert.Subject)
	root.Children["subjectPublicKeyInfo"] = buildSubjectPublicKeyInfo(cert)

	if metadata != nil {
		projectUniqueIdentifier(root, "issuerUniqueID", metadata.IssuerUniqueID)
		projectUniqueIdentifier(root, "subjectUniqueID", metadata.SubjectUniqueID)
	}

	parsedExtensions := map[string]*node.Node{}
	if len(cert.Extensions) > 0 {
		root.Children["extensions"] = x509node.BuildExtensions(cert.Extensions)
		parsedExtensions = parseCertificateExtensions(root.Children["extensions"], cert.Extensions)
	}

	setChild(root, "keyUsage", projectWithFallback(
		parsedExtensions[oid.KeyUsage],
		extensions.Lookup(oid.KeyUsage).Present(),
		func() *node.Node { return buildKeyUsage(cert.KeyUsage) },
	))
	setChild(root, "extKeyUsage", projectWithFallback(
		parsedExtensions[oid.ExtendedKeyUsage],
		len(cert.ExtKeyUsage) > 0,
		func() *node.Node { return buildExtKeyUsage(cert.ExtKeyUsage) },
	))
	setChild(root, "basicConstraints", projectWithFallback(
		parsedExtensions[oid.BasicConstraints],
		cert.BasicConstraintsValid,
		func() *node.Node { return buildBasicConstraints(cert) },
	))

	for identifier, name := range map[string]string{
		oid.PolicyMappings:    "policyMappings",
		oid.PolicyConstraints: "policyConstraints",
		oid.InhibitAnyPolicy:  "inhibitAnyPolicy",
	} {
		if projected := parsedExtensions[identifier]; projected != nil {
			root.Children[name] = projected
		}
	}

	if len(cert.SubjectKeyId) > 0 {
		root.Children["subjectKeyIdentifier"] = node.New("subjectKeyIdentifier", cert.SubjectKeyId)
	}

	if len(cert.AuthorityKeyId) > 0 {
		root.Children["authorityKeyIdentifier"] = node.New("authorityKeyIdentifier", cert.AuthorityKeyId)
	}

	if extensions.Lookup(oid.SubjectAlternativeName).Present() {
		root.Children["subjectAltName"] = buildSubjectAltName(extensions)
		mirrorGeneralNamesMalformed(
			root.Children["extensions"],
			oid.SubjectAlternativeName,
			root.Children["subjectAltName"],
		)
	}

	// Add Issuer Alt Name (IAN)
	if extensions.Lookup(oid.IssuerAlternativeName).Present() {
		root.Children["issuerAltName"] = buildIssuerAltName(extensions)
		mirrorGeneralNamesMalformed(
			root.Children["extensions"],
			oid.IssuerAlternativeName,
			root.Children["issuerAltName"],
		)
	}

	// Add Name Constraints (for CA certificates)
	projectedNameConstraints := parsedExtensions[oid.NameConstraints]
	if projectedNameConstraints != nil {
		if extension, ok := extensions.Lookup(oid.NameConstraints).First(); ok {
			projectedNameConstraints.Children["critical"] = node.New("critical", extension.Critical)
		}
	}
	setChild(root, "nameConstraints", projectWithFallback(
		projectedNameConstraints,
		hasNameConstraints(cert),
		func() *node.Node { return buildNameConstraints(cert) },
	))

	// Add CABF Organization Identifier (for EV certificates)
	if cert.CABFOrganizationIdentifier != nil {
		root.Children["cabfOrganizationIdentifier"] = buildCABFOrganizationID(cert)
	}

	if len(cert.Signature) > 0 {
		root.Children["signatureValue"] = node.New("signatureValue", cert.Signature)
	}

	// Add Signed Certificate Timestamps (SCT) from CT extension
	if len(cert.SignedCertificateTimestampList) > 0 {
		sctNode := node.New("signedCertificateTimestamps", nil)
		for i, sct := range cert.SignedCertificateTimestampList {
			sctNode.Children[strconv.Itoa(i)] = buildSCT(sct, i)
		}
		root.Children["signedCertificateTimestamps"] = sctNode
	}

	return root
}

func buildSerialNumber(cert *x509.Certificate, metadata *tbsCertificateMetadata) *node.Node {
	if cert.SerialNumber == nil {
		return nil
	}
	serialNode := node.New("serialNumber", cert.SerialNumber.Bytes())
	if metadata != nil {
		serialBytes := append([]byte(nil), metadata.SerialNumber.Value...)
		serialNode.Value = serialBytes
		serialNode.Children["raw"] = node.New(
			"raw",
			append([]byte(nil), metadata.SerialNumber.RawDER...),
		)
		serialNode.Children["length"] = node.New("length", len(serialBytes))
	}
	serialNode.Children["value"] = node.New("value", cert.SerialNumber.String())
	return serialNode
}

// parseCertificateExtensions runs the strict parser for each supported
// extension, merges the parsed children into the generic extension node and
// returns the parsed projections by OID. A parse failure marks the generic
// node malformed and records a malformed projection that keeps the raw value.
func parseCertificateExtensions(extensionsNode *node.Node, extensions []pkix.Extension) map[string]*node.Node {
	parsedExtensions := make(map[string]*node.Node)
	seenExtensions := make(map[string]struct{}, len(extensions))
	for _, ext := range extensions {
		oidStr := ext.Id.String()
		if _, duplicate := seenExtensions[oidStr]; duplicate {
			continue
		}
		seenExtensions[oidStr] = struct{}{}
		parser, supported := certificateExtensionParsers[oidStr]
		if !supported {
			continue
		}
		extNode := extensionsNode.Children[oidStr]
		parsed, err := parser(ext.Value)
		if err != nil {
			extNode.Children["malformed"] = node.New("malformed", true)
			name, _ := oid.ExtensionName(oidStr)
			parsedExtensions[oidStr] = malformedExtensionNodeWithRaw(name, ext.Value)
			continue
		}
		parsedExtensions[oidStr] = parsed
		for name, child := range parsed.Children {
			extNode.Children[name] = child
		}
	}
	return parsedExtensions
}

// projectWithFallback prefers the strictly parsed projection of an extension.
// When strict parsing failed but zcrypto still recovered typed values
// (recovered), those values are projected instead, keeping the malformed
// marker and raw bytes. Without a parsed projection the typed values are used
// when recovered, and nil is returned otherwise.
func projectWithFallback(parsed *node.Node, recovered bool, buildRecovered func() *node.Node) *node.Node {
	if parsed == nil {
		if recovered {
			return buildRecovered()
		}
		return nil
	}
	if parsed.Children["malformed"] == nil || !recovered {
		return parsed
	}
	fallback := buildRecovered()
	fallback.Children["malformed"] = node.New("malformed", true)
	fallback.Children["raw"] = parsed.Children["raw"]
	return fallback
}

func setChild(parent *node.Node, name string, child *node.Node) {
	if child != nil {
		parent.Children[name] = child
	}
}

func mirrorGeneralNamesMalformed(extensions *node.Node, identifier string, projected *node.Node) {
	if extensions == nil || projected == nil || projected.Children["malformed"] == nil {
		return
	}
	extension := extensions.Children[identifier]
	if extension != nil {
		extension.Children["malformed"] = node.New("malformed", true)
	}
}

func buildSignatureAlgorithm(cert *x509.Certificate) *node.Node {
	params := x509asn1.ParseSignedObjectAlgorithmParams(cert.Raw)
	return x509node.BuildAlgorithmIdentifier("signatureAlgorithm", cert.SignatureAlgorithm.String(), params)
}

func buildTBSSignatureAlgorithm(cert *x509.Certificate) *node.Node {
	params := parseTBSCertSignatureParams(cert.RawTBSCertificate)
	return x509node.BuildAlgorithmIdentifier("tbsSignatureAlgorithm", cert.SignatureAlgorithm.String(), params)
}

func projectTBSCertificateMetadata(root *node.Node, rawTBSCertificate []byte) *tbsCertificateMetadata {
	if len(rawTBSCertificate) == 0 {
		return nil
	}

	tbsNode := node.New("tbsCertificate", nil)
	tbsNode.Children["raw"] = node.New("raw", append([]byte(nil), rawTBSCertificate...))
	root.Children["tbsCertificate"] = tbsNode

	metadata, err := parseTBSCertificateMetadata(rawTBSCertificate)
	if err != nil {
		tbsNode.Children["malformed"] = node.New("malformed", true)
		return nil
	}
	return &metadata
}

func buildValidity(cert *x509.Certificate, metadata *tbsCertificateMetadata) *node.Node {
	n := node.New("validity", nil)

	notBeforeNode := node.New("notBefore", cert.NotBefore)
	notAfterNode := node.New("notAfter", cert.NotAfter)

	if metadata != nil {
		addTimeEncoding(notBeforeNode, metadata.Validity.NotBefore)
		addTimeEncoding(notAfterNode, metadata.Validity.NotAfter)
	}

	n.Children["notBefore"] = notBeforeNode
	n.Children["notAfter"] = notAfterNode
	return n
}

func addTimeEncoding(target *node.Node, encoding x509asn1.TimeEncoding) {
	target.Children["encoding"] = node.New("encoding", encoding.Tag)
	target.Children["raw"] = node.New("raw", append([]byte(nil), encoding.RawDER...))
	target.Children["rawValue"] = node.New("rawValue", encoding.RawValue)
	target.Children["hasFraction"] = node.New("hasFraction", encoding.HasFraction)
	target.Children["hasSeconds"] = node.New("hasSeconds", encoding.HasSeconds)
	target.Children["hasZulu"] = node.New("hasZulu", encoding.HasZulu)
}

func projectUniqueIdentifier(parent *node.Node, name string, metadata *uniqueIdentifierMetadata) {
	if metadata == nil {
		return
	}

	value := append([]byte(nil), metadata.Value...)
	n := node.New(name, value)
	n.Children["raw"] = node.New("raw", append([]byte(nil), metadata.RawDER...))
	n.Children["value"] = node.New("value", append([]byte(nil), value...))
	n.Children["unusedBits"] = node.New("unusedBits", metadata.UnusedBits)
	n.Children["bitLength"] = node.New("bitLength", metadata.BitLength)
	parent.Children[name] = n
}

func buildSubjectPublicKeyInfo(cert *x509.Certificate) *node.Node {
	n := node.New("subjectPublicKeyInfo", nil)

	params := parseSubjectPublicKeyInfoParams(cert.RawSubjectPublicKeyInfo)
	algo := x509node.BuildAlgorithmIdentifier("algorithm", cert.PublicKeyAlgorithm.String(), params)
	n.Children["algorithm"] = algo

	if cert.PublicKey != nil {
		switch key := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			n.Children["publicKey"] = buildRSAKey(key)
		case *dsa.PublicKey:
			n.Children["publicKey"] = buildDSAKey(key)
		case *x509.AugmentedECDSA:
			// zcrypto wraps parsed ECDSA keys together with their raw bits.
			n.Children["publicKey"] = buildECDSAKey(key.Pub)
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

func buildRSAKey(key *rsa.PublicKey) *node.Node {
	n := node.New("publicKey", nil)
	n.Children["keySize"] = node.New("keySize", key.N.BitLen())
	n.Children["exponent"] = node.New("exponent", key.E)
	return n
}

// buildDSAKey projects the sizes of a zcrypto DSA key. Parameters inherited
// from an issuer are zero until acquisition resolves them, so their sizes are
// unknown and omitted.
func buildDSAKey(key *dsa.PublicKey) *node.Node {
	n := node.New("publicKey", nil)
	if key.P != nil && key.P.Sign() > 0 {
		n.Children["keySize"] = node.New("keySize", key.P.BitLen())
	}
	if key.Q != nil && key.Q.Sign() > 0 {
		n.Children["subgroupSize"] = node.New("subgroupSize", key.Q.BitLen())
	}
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

func buildSCT(ctSCT *ct.SignedCertificateTimestamp, index int) *node.Node {
	n := node.New(strconv.Itoa(index), nil)
	n.Children["present"] = node.New("present", true)
	if ctSCT == nil {
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

	setChild(n, "permittedSubtrees", buildNameConstraintSubtrees(
		"permittedSubtrees",
		cert.PermittedDNSNames,
		cert.PermittedEmailAddresses,
		cert.PermittedURIs,
		cert.PermittedIPAddresses,
		cert.PermittedDirectoryNames,
	))
	setChild(n, "excludedSubtrees", buildNameConstraintSubtrees(
		"excludedSubtrees",
		cert.ExcludedDNSNames,
		cert.ExcludedEmailAddresses,
		cert.ExcludedURIs,
		cert.ExcludedIPAddresses,
		cert.ExcludedDirectoryNames,
	))

	return n
}

// buildNameConstraintSubtrees projects one subtrees list per name form, or
// returns nil when every list is empty.
func buildNameConstraintSubtrees(
	name string,
	dnsNames, emailAddresses, uris []x509.GeneralSubtreeString,
	ipAddresses []x509.GeneralSubtreeIP,
	directoryNames []x509.GeneralSubtreeName,
) *node.Node {
	n := node.New(name, nil)
	stringSubtree := func(subtree x509.GeneralSubtreeString) (*node.Node, int, int) {
		return node.New("value", subtree.Data), subtree.Min, subtree.Max
	}
	buildGeneralSubtrees(n, "dNSName", dnsNames, stringSubtree)
	buildGeneralSubtrees(n, "rfc822Name", emailAddresses, stringSubtree)
	buildGeneralSubtrees(n, "uniformResourceIdentifier", uris, stringSubtree)
	buildGeneralSubtrees(n, "iPAddress", ipAddresses, func(subtree x509.GeneralSubtreeIP) (*node.Node, int, int) {
		return node.New("value", subtree.Data.String()), subtree.Min, subtree.Max
	})
	buildGeneralSubtrees(n, "directoryName", directoryNames, func(subtree x509.GeneralSubtreeName) (*node.Node, int, int) {
		return x509node.BuildPkixName("value", subtree.Data), subtree.Min, subtree.Max
	})
	if len(n.Children) == 0 {
		return nil
	}
	return n
}

func buildGeneralSubtrees[T any](
	parent *node.Node,
	name string,
	subtrees []T,
	project func(T) (value *node.Node, minimum, maximum int),
) {
	if len(subtrees) == 0 {
		return
	}
	subtreeNode := node.New(name, nil)
	for i, subtree := range subtrees {
		key := strconv.Itoa(i)
		child := node.New(key, nil)
		value, minimum, maximum := project(subtree)
		child.Children["value"] = value
		if minimum > 0 {
			child.Children["min"] = node.New("min", minimum)
		}
		if maximum > 0 {
			child.Children["max"] = node.New("max", maximum)
		}
		subtreeNode.Children[key] = child
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
