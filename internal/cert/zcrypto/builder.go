package zcrypto

import (
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
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
	root.Children["issuer"] = buildPkixName("issuer", cert.Issuer)
	root.Children["validity"] = buildValidity(cert)
	root.Children["subject"] = buildPkixName("subject", cert.Subject)
	root.Children["subjectPublicKeyInfo"] = buildSubjectPublicKeyInfo(cert)

	if cert.IssuerUniqueId.BitLength > 0 {
		root.Children["issuerUniqueID"] = node.New("issuerUniqueID", cert.IssuerUniqueId.Bytes)
	}

	if cert.SubjectUniqueId.BitLength > 0 {
		root.Children["subjectUniqueID"] = node.New("subjectUniqueID", cert.SubjectUniqueId.Bytes)
	}

	if len(cert.Extensions) > 0 {
		root.Children["extensions"] = buildExtensions(cert)
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

	if len(cert.Signature) > 0 {
		root.Children["signatureValue"] = node.New("signatureValue", cert.Signature)
	}

	return root
}

func buildSignatureAlgorithm(cert *x509.Certificate) *node.Node {
	n := node.New("signatureAlgorithm", nil)
	n.Children["algorithm"] = node.New("algorithm", cert.SignatureAlgorithm.String())
	if len(cert.SignatureAlgorithmOID) > 0 {
		n.Children["oid"] = node.New("oid", cert.SignatureAlgorithmOID.String())
	}
	return n
}

func buildValidity(cert *x509.Certificate) *node.Node {
	n := node.New("validity", nil)
	n.Children["notBefore"] = node.New("notBefore", cert.NotBefore)
	n.Children["notAfter"] = node.New("notAfter", cert.NotAfter)
	return n
}

func buildSubjectPublicKeyInfo(cert *x509.Certificate) *node.Node {
	n := node.New("subjectPublicKeyInfo", nil)

	algo := node.New("algorithm", nil)
	algo.Children["algorithm"] = node.New("algorithm", cert.PublicKeyAlgorithm.String())
	if len(cert.PublicKeyAlgorithmOID) > 0 {
		algo.Children["oid"] = node.New("oid", cert.PublicKeyAlgorithmOID.String())
	}
	n.Children["algorithm"] = algo

	if cert.PublicKey != nil {
		switch key := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			n.Children["publicKey"] = buildRSAKey(key)
		case *ecdsa.PublicKey:
			n.Children["publicKey"] = buildECDSAKey(key)
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
		n.Children["contentCommitment"] = node.New("contentCommitment", true)
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

func buildExtensions(cert *x509.Certificate) *node.Node {
	n := node.New("extensions", nil)

	for _, ext := range cert.Extensions {
		extNode := node.New(ext.Id.String(), nil)
		extNode.Children["oid"] = node.New("oid", ext.Id.String())
		extNode.Children["critical"] = node.New("critical", ext.Critical)
		extNode.Children["value"] = node.New("value", ext.Value)
		n.Children[ext.Id.String()] = extNode
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

func buildPkixName(name string, pkixName pkix.Name) *node.Node {
	n := node.New(name, nil)

	if len(pkixName.Country) > 0 {
		n.Children["countryName"] = node.New("countryName", pkixName.Country[0])
	}
	if len(pkixName.Organization) > 0 {
		n.Children["organizationName"] = node.New("organizationName", pkixName.Organization[0])
	}
	if len(pkixName.OrganizationalUnit) > 0 {
		n.Children["organizationalUnitName"] = node.New("organizationalUnitName", pkixName.OrganizationalUnit[0])
	}
	if pkixName.CommonName != "" {
		n.Children["commonName"] = node.New("commonName", pkixName.CommonName)
	}
	if len(pkixName.Locality) > 0 {
		n.Children["localityName"] = node.New("localityName", pkixName.Locality[0])
	}
	if len(pkixName.Province) > 0 {
		n.Children["stateOrProvinceName"] = node.New("stateOrProvinceName", pkixName.Province[0])
	}
	if len(pkixName.StreetAddress) > 0 {
		n.Children["streetAddress"] = node.New("streetAddress", pkixName.StreetAddress[0])
	}
	if len(pkixName.PostalCode) > 0 {
		n.Children["postalCode"] = node.New("postalCode", pkixName.PostalCode[0])
	}
	if pkixName.SerialNumber != "" {
		n.Children["serialNumber"] = node.New("serialNumber", pkixName.SerialNumber)
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
