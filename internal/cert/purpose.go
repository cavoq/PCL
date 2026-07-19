package cert

import (
	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/zmap/zcrypto/x509"
)

const anyExtendedKeyUsageOID = "2.5.29.37.0"

type applicationPurpose struct {
	usage  x509.ExtKeyUsage
	oid    string
	custom bool
}

// ApplicationPurposeValid reports whether the current certificate permits an
// explicitly requested application purpose. Extended Key Usage is enforced on
// every certificate, while Key Usage compatibility is checked only for end
// entities: a CA can constrain subordinate purposes with EKU while using its
// own key exclusively for certificate signing.
//
// An absent EKU or Key Usage extension is unrestricted for its dimension. An
// empty or unrecognized friendly purpose is invalid; canonical dotted OIDs are
// accepted so private EKUs can be selected without teaching PCL their names.
func ApplicationPurposeValid(current *Info, purpose string) bool {
	if current == nil || current.Cert == nil {
		return false
	}

	requested, ok := parseApplicationPurpose(purpose)
	if !ok || !extendedKeyUsagePermits(current.Cert, requested) {
		return false
	}

	basicConstraints, valid := basicConstraintsProfileFacts(current.Cert)
	if !valid {
		return false
	}
	if basicConstraints.CA {
		return true
	}
	return keyUsagePermits(current.Cert, requested)
}

// AnyExtendedKeyUsageNotCritical checks the RFC 5280 recommendation that the
// anyExtendedKeyUsage KeyPurposeId not appear in a critical EKU extension.
// Other EKU values are unaffected by this profile predicate.
func AnyExtendedKeyUsageNotCritical(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}

	for _, extension := range certificate.Extensions {
		if extension.Id.String() != oid.ExtendedKeyUsage {
			continue
		}
		identifiers, err := certzcrypto.DecodeExtendedKeyUsageOIDsStrict(extension.Value)
		if err != nil {
			return false
		}
		for _, identifier := range identifiers {
			if identifier == anyExtendedKeyUsageOID {
				return !extension.Critical
			}
		}
		return true
	}
	return true
}

func parseApplicationPurpose(value string) (applicationPurpose, bool) {
	if value == "any" || value == "anyExtendedKeyUsage" || value == anyExtendedKeyUsageOID {
		// anyExtendedKeyUsage is a wildcard assertion made by a certificate,
		// not a concrete application purpose a caller can request.
		return applicationPurpose{}, false
	}

	if usage, ok := oid.ExtKeyUsage(value); ok {
		identifier, hasIdentifier := oid.ExtKeyUsageOID(value)
		if !hasIdentifier {
			return applicationPurpose{}, false
		}
		return applicationPurpose{usage: usage, oid: identifier}, true
	}

	if !oid.ValidDotted(value) {
		return applicationPurpose{}, false
	}
	if usage, ok := applicationPurposeUsageByOID(value); ok {
		return applicationPurpose{usage: usage, oid: value}, true
	}
	return applicationPurpose{oid: value, custom: true}, true
}

func applicationPurposeUsageByOID(identifier string) (x509.ExtKeyUsage, bool) {
	for _, name := range []string{
		"serverAuth",
		"clientAuth",
		"codeSigning",
		"emailProtection",
		"timeStamping",
		"ocspSigning",
	} {
		candidate, ok := oid.ExtKeyUsageOID(name)
		if !ok || candidate != identifier {
			continue
		}
		usage, ok := oid.ExtKeyUsage(name)
		return usage, ok
	}
	return 0, false
}

func extendedKeyUsagePermits(certificate *x509.Certificate, requested applicationPurpose) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.String() != oid.ExtendedKeyUsage {
			continue
		}

		identifiers, err := certzcrypto.DecodeExtendedKeyUsageOIDsStrict(extension.Value)
		if err != nil {
			return false
		}
		for _, identifier := range identifiers {
			if identifier == anyExtendedKeyUsageOID || identifier == requested.oid {
				return true
			}
		}
		return false
	}
	return true
}

func keyUsagePermits(certificate *x509.Certificate, requested applicationPurpose) bool {
	if !certificateHasExtension(certificate, oid.KeyUsage) {
		return true
	}
	if !KeyUsageDependenciesValid(certificate) || certificate.KeyUsage == 0 {
		return false
	}

	// A private EKU does not define a particular key operation in RFC 5280.
	// When Key Usage is present, fail closed instead of inventing a mapping.
	if requested.custom || requested.usage == x509.ExtKeyUsageAny {
		return false
	}

	var compatible x509.KeyUsage
	switch requested.usage {
	case x509.ExtKeyUsageServerAuth:
		compatible = x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement
	case x509.ExtKeyUsageClientAuth:
		compatible = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	case x509.ExtKeyUsageCodeSigning:
		compatible = x509.KeyUsageDigitalSignature
	case x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOcspSigning:
		compatible = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	case x509.ExtKeyUsageEmailProtection:
		compatible = x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement
	default:
		return false
	}
	return certificate.KeyUsage&compatible != 0
}
