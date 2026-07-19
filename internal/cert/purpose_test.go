package cert

import (
	"testing"

	"github.com/cavoq/PCL/internal/oid"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestApplicationPurposeValidEKUSelection(t *testing.T) {
	serverAuthOID := oidForCertificateTest(t, oid.ServerAuth)
	customOID := oidForCertificateTest(t, "1.2.3.4")
	serverExtension := extendedKeyUsageExtensionForCertificateTest(t, false, oid.ServerAuth)
	clientExtension := extendedKeyUsageExtensionForCertificateTest(t, false, oid.ClientAuth)
	anyExtension := extendedKeyUsageExtensionForCertificateTest(t, false, anyExtendedKeyUsageOID)
	customExtension := extendedKeyUsageExtensionForCertificateTest(t, false, customOID.String())

	tests := []struct {
		name        string
		certificate *x509.Certificate
		purpose     string
		want        bool
	}{
		{name: "nil certificate", purpose: "serverAuth"},
		{name: "missing purpose", certificate: &x509.Certificate{}},
		{name: "unknown friendly purpose", certificate: &x509.Certificate{}, purpose: "webServer"},
		{name: "malformed dotted purpose", certificate: &x509.Certificate{}, purpose: "1.03.6"},
		{
			name:        "absent EKU and KU are unrestricted",
			certificate: &x509.Certificate{},
			purpose:     "serverAuth",
			want:        true,
		},
		{
			name: "matching friendly EKU",
			certificate: &x509.Certificate{
				Extensions:  []pkix.Extension{serverExtension},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			purpose: "serverAuth",
			want:    true,
		},
		{
			name: "matching dotted standard EKU",
			certificate: &x509.Certificate{
				Extensions:  []pkix.Extension{serverExtension},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			purpose: serverAuthOID.String(),
			want:    true,
		},
		{
			name: "mismatched EKU",
			certificate: &x509.Certificate{
				Extensions:  []pkix.Extension{clientExtension},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			purpose: "serverAuth",
		},
		{
			name: "present empty EKU is not unrestricted",
			certificate: &x509.Certificate{
				Extensions: []pkix.Extension{extendedKeyUsageExtensionForCertificateTest(t, false)},
			},
			purpose: "serverAuth",
		},
		{
			name: "certificate anyExtendedKeyUsage permits standard purpose",
			certificate: &x509.Certificate{
				Extensions:  []pkix.Extension{anyExtension},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			},
			purpose: "serverAuth",
			want:    true,
		},
		{
			name: "friendly anyExtendedKeyUsage is not an application purpose",
			certificate: &x509.Certificate{
				Extensions:  []pkix.Extension{serverExtension},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			purpose: "anyExtendedKeyUsage",
		},
		{
			name: "dotted anyExtendedKeyUsage is not an application purpose",
			certificate: &x509.Certificate{
				Extensions:  []pkix.Extension{serverExtension},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			purpose: anyExtendedKeyUsageOID,
		},
		{
			name: "any is not an application purpose",
			certificate: &x509.Certificate{
				Extensions:         []pkix.Extension{customExtension},
				UnknownExtKeyUsage: []zasn1.ObjectIdentifier{customOID},
			},
			purpose: "any",
		},
		{
			name: "matching private EKU",
			certificate: &x509.Certificate{
				Extensions:         []pkix.Extension{customExtension},
				UnknownExtKeyUsage: []zasn1.ObjectIdentifier{customOID},
			},
			purpose: customOID.String(),
			want:    true,
		},
		{
			name: "mismatched private EKU",
			certificate: &x509.Certificate{
				Extensions:         []pkix.Extension{customExtension},
				UnknownExtKeyUsage: []zasn1.ObjectIdentifier{customOID},
			},
			purpose: "1.2.3.5",
		},
		{
			name: "matching recognized EKU outside friendly catalog",
			certificate: &x509.Certificate{
				Extensions: []pkix.Extension{
					extendedKeyUsageExtensionForCertificateTest(t, false, "1.3.6.1.5.5.7.3.5"),
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageIpsecEndSystem},
			},
			purpose: "1.3.6.1.5.5.7.3.5",
			want:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := &Info{Cert: test.certificate}
			if got := ApplicationPurposeValid(current, test.purpose); got != test.want {
				t.Fatalf("ApplicationPurposeValid() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestApplicationPurposeValidKeyUsageCompatibility(t *testing.T) {
	base := func(keyUsage x509.KeyUsage) *x509.Certificate {
		return &x509.Certificate{
			Extensions: []pkix.Extension{
				extendedKeyUsageExtensionForCertificateTest(t, false, oid.ServerAuth),
				extensionForCertificateTest(oid.KeyUsage),
			},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:    keyUsage,
		}
	}

	tests := []struct {
		name        string
		certificate *x509.Certificate
		want        bool
	}{
		{name: "digital signature", certificate: base(x509.KeyUsageDigitalSignature), want: true},
		{name: "key encipherment", certificate: base(x509.KeyUsageKeyEncipherment), want: true},
		{name: "unrelated CRL signing", certificate: base(x509.KeyUsageCRLSign)},
		{name: "structurally invalid encipher only", certificate: base(x509.KeyUsageEncipherOnly)},
		{
			name: "CA EKU constrains subordinates without end entity KU mapping",
			certificate: func() *x509.Certificate {
				certificate := base(x509.KeyUsageCertSign)
				certificate.BasicConstraintsValid = true
				certificate.IsCA = true
				return certificate
			}(),
			want: true,
		},
		{
			name: "raw CA fact bypasses end entity KU mapping",
			certificate: func() *x509.Certificate {
				certificate := base(x509.KeyUsageCertSign)
				basicConstraints := extensionForCertificateTest(oid.BasicConstraints)
				basicConstraints.Value = []byte{0x30, 0x03, 0x01, 0x01, 0xff}
				certificate.Extensions = append(certificate.Extensions, basicConstraints)
				return certificate
			}(),
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ApplicationPurposeValid(&Info{Cert: test.certificate}, "serverAuth"); got != test.want {
				t.Fatalf("ApplicationPurposeValid() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestApplicationPurposeValidSpecificKeyUsageMappings(t *testing.T) {
	certificate := func(usage x509.ExtKeyUsage, keyUsage x509.KeyUsage) *x509.Certificate {
		identifier := oid.ExtKeyUsageToOID(usage)
		if identifier == "" {
			t.Fatalf("no test OID for extended key usage %v", usage)
		}
		return &x509.Certificate{
			Extensions: []pkix.Extension{
				extendedKeyUsageExtensionForCertificateTest(t, false, identifier),
				extensionForCertificateTest(oid.KeyUsage),
			},
			ExtKeyUsage: []x509.ExtKeyUsage{usage},
			KeyUsage:    keyUsage,
		}
	}
	customOID := oidForCertificateTest(t, "1.2.3.4")

	tests := []struct {
		name        string
		certificate *x509.Certificate
		purpose     string
		want        bool
	}{
		{
			name:        "code signing permits digital signature",
			certificate: certificate(x509.ExtKeyUsageCodeSigning, x509.KeyUsageDigitalSignature),
			purpose:     "codeSigning",
			want:        true,
		},
		{
			name:        "code signing does not permit content commitment",
			certificate: certificate(x509.ExtKeyUsageCodeSigning, x509.KeyUsageContentCommitment),
			purpose:     "codeSigning",
		},
		{
			name: "private purpose with KU fails closed",
			certificate: &x509.Certificate{
				Extensions: []pkix.Extension{
					extendedKeyUsageExtensionForCertificateTest(t, false, customOID.String()),
					extensionForCertificateTest(oid.KeyUsage),
				},
				UnknownExtKeyUsage: []zasn1.ObjectIdentifier{customOID},
				KeyUsage:           x509.KeyUsageCRLSign,
			},
			purpose: customOID.String(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ApplicationPurposeValid(&Info{Cert: test.certificate}, test.purpose); got != test.want {
				t.Fatalf("ApplicationPurposeValid() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAnyExtendedKeyUsageNotCritical(t *testing.T) {
	extension := extendedKeyUsageExtensionForCertificateTest(t, false, anyExtendedKeyUsageOID)
	criticalExtension := extension
	criticalExtension.Critical = true
	specificCriticalExtension := extendedKeyUsageExtensionForCertificateTest(t, true, oid.ServerAuth)

	tests := []struct {
		name        string
		certificate *x509.Certificate
		want        bool
	}{
		{name: "nil certificate"},
		{name: "extension absent", certificate: &x509.Certificate{}, want: true},
		{
			name: "specific purpose may be critical",
			certificate: &x509.Certificate{
				Extensions:  []pkix.Extension{specificCriticalExtension},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			want: true,
		},
		{
			name: "non-critical any purpose",
			certificate: &x509.Certificate{
				Extensions:  []pkix.Extension{extension},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			},
			want: true,
		},
		{
			name: "critical any purpose",
			certificate: &x509.Certificate{
				Extensions:  []pkix.Extension{criticalExtension},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			},
		},
		{
			name: "malformed extension fails closed",
			certificate: &x509.Certificate{
				Extensions: []pkix.Extension{extensionForCertificateTest(oid.ExtendedKeyUsage)},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := AnyExtendedKeyUsageNotCritical(test.certificate); got != test.want {
				t.Fatalf("AnyExtendedKeyUsageNotCritical() = %v, want %v", got, test.want)
			}
		})
	}
}

func extensionForCertificateTest(identifier string) pkix.Extension {
	return pkix.Extension{Id: oidForCertificateTestNoError(identifier)}
}

func extendedKeyUsageExtensionForCertificateTest(
	t *testing.T,
	critical bool,
	identifiers ...string,
) pkix.Extension {
	t.Helper()

	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		for _, identifier := range identifiers {
			parsed, err := oid.Parse(identifier)
			if err != nil {
				t.Fatalf("parse test EKU OID %q: %v", identifier, err)
			}
			sequence.AddASN1ObjectIdentifier(parsed)
		}
	})
	extension := extensionForCertificateTest(oid.ExtendedKeyUsage)
	extension.Critical = critical
	extension.Value = builder.BytesOrPanic()
	return extension
}

func oidForCertificateTest(t *testing.T, identifier string) zasn1.ObjectIdentifier {
	t.Helper()
	result := oidForCertificateTestNoError(identifier)
	if result == nil {
		t.Fatalf("invalid test OID %q", identifier)
	}
	return result
}

func oidForCertificateTestNoError(identifier string) zasn1.ObjectIdentifier {
	parsed, err := oid.Parse(identifier)
	if err != nil {
		return nil
	}
	result := make(zasn1.ObjectIdentifier, len(parsed))
	copy(result, parsed)
	return result
}
