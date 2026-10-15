package x509ext

import (
	"slices"
	"testing"

	"github.com/cavoq/PCL/internal/oid"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestCertificateExtensionChecksCoverProcessedRegistry(t *testing.T) {
	checked := make([]string, 0, len(certificateExtensionChecks))
	for identifier := range certificateExtensionChecks {
		checked = append(checked, identifier)
	}
	slices.Sort(checked)
	if registered := oid.ProcessedExtensionsAt(oid.ExtensionInCertificate); !slices.Equal(checked, registered) {
		t.Fatalf("certificate extension checks %v, processed registry %v", checked, registered)
	}
}

func TestCertificateCriticalExtensionsProcessable(t *testing.T) {
	var (
		keyUsage          = zasn1.ObjectIdentifier{2, 5, 29, 15}
		basicConstraints  = zasn1.ObjectIdentifier{2, 5, 29, 19}
		nameConstraints   = zasn1.ObjectIdentifier{2, 5, 29, 30}
		policies          = zasn1.ObjectIdentifier{2, 5, 29, 32}
		subjectKeyID      = zasn1.ObjectIdentifier{2, 5, 29, 14}
		unknown           = zasn1.ObjectIdentifier{1, 2, 3, 4}
		validKeyUsage     = []byte{0x03, 0x02, 0x05, 0xa0}
		validCA           = []byte{0x30, 0x03, 0x01, 0x01, 0xff}
		malformedKeyUsage = []byte{0x04, 0x00}
		// permittedSubtrees with a registeredID base, which name constraint
		// processing does not support.
		unsupportedNameForm = []byte{0x30, 0x08, 0xa0, 0x06, 0x30, 0x04, 0x88, 0x02, 0x2a, 0x03}
		// One policy with a qualifier of unknown type 1.2.4.
		unknownQualifier = []byte{
			0x30, 0x10, 0x30, 0x0e, 0x06, 0x02, 0x2a, 0x03,
			0x30, 0x08, 0x30, 0x06, 0x06, 0x02, 0x2a, 0x04,
			0x05, 0x00,
		}
	)
	extension := func(identifier zasn1.ObjectIdentifier, critical bool, value []byte) pkix.Extension {
		return pkix.Extension{Id: identifier, Critical: critical, Value: value}
	}

	tests := []struct {
		name       string
		extensions []pkix.Extension
		want       bool
	}{
		{name: "no extensions", want: true},
		{
			name: "processed critical extensions",
			extensions: []pkix.Extension{
				extension(keyUsage, true, validKeyUsage),
				extension(basicConstraints, true, validCA),
			},
			want: true,
		},
		{
			name:       "noncritical unknown and malformed extensions",
			extensions: []pkix.Extension{extension(unknown, false, nil), extension(keyUsage, false, malformedKeyUsage)},
			want:       true,
		},
		{
			name:       "noncritical unprocessed content",
			extensions: []pkix.Extension{extension(nameConstraints, false, unsupportedNameForm)},
			want:       true,
		},
		{name: "critical unknown extension", extensions: []pkix.Extension{extension(unknown, true, nil)}},
		{
			name:       "critical known but unprocessed extension",
			extensions: []pkix.Extension{extension(subjectKeyID, true, []byte{0x04, 0x01, 0x01})},
		},
		{name: "critical malformed extension", extensions: []pkix.Extension{extension(keyUsage, true, malformedKeyUsage)}},
		{
			name:       "critical unsupported name constraint form",
			extensions: []pkix.Extension{extension(nameConstraints, true, unsupportedNameForm)},
		},
		{
			name:       "critical unknown policy qualifier",
			extensions: []pkix.Extension{extension(policies, true, unknownQualifier)},
		},
		{
			name: "duplicate noncritical OID",
			extensions: []pkix.Extension{
				extension(keyUsage, false, validKeyUsage),
				extension(keyUsage, false, validKeyUsage),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := CertificateCriticalExtensionsProcessable(test.extensions); got != test.want {
				t.Fatalf("CertificateCriticalExtensionsProcessable() = %v, want %v", got, test.want)
			}
		})
	}
}
