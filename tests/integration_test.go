package tests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
	"gopkg.in/yaml.v3"

	derasn1 "github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/cert"
	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

func TestIntegrationPolicies(t *testing.T) {
	caseFiles, err := filepath.Glob(filepath.Join("policy-cases", "*.yaml"))
	if err != nil {
		t.Fatalf("unexpected glob error: %v", err)
	}
	if len(caseFiles) == 0 {
		t.Fatalf("no test cases found")
	}

	for _, caseFile := range caseFiles {
		tc, err := loadCase(caseFile)
		if err != nil {
			t.Fatalf("failed to load case %s: %v", caseFile, err)
		}
		t.Run(tc.Name, func(t *testing.T) {
			runCase(t, filepath.Dir(caseFile), tc)
		})
	}
}

type testCase struct {
	Name               string            `yaml:"name"`
	Policy             string            `yaml:"policy"`
	Fixture            string            `yaml:"fixture,omitempty"`
	Rules              []string          `yaml:"rules,omitempty"`
	Certs              string            `yaml:"certs"`
	Issuers            []string          `yaml:"issuers,omitempty"`
	CRL                string            `yaml:"crl,omitempty"`
	OCSP               string            `yaml:"ocsp,omitempty"`
	ApplicationPurpose string            `yaml:"application_purpose,omitempty"`
	EvalTime           string            `yaml:"eval_time,omitempty"`
	WantCRLLoadError   bool              `yaml:"want_crl_load_error,omitempty"`
	Expected           map[string]counts `yaml:"expected"`
}

type counts struct {
	Pass int `yaml:"pass"`
	Fail int `yaml:"fail"`
	Skip int `yaml:"skip"`
}

func loadCase(path string) (testCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return testCase{}, err
	}
	var tc testCase
	if err := yaml.Unmarshal(data, &tc); err != nil {
		return testCase{}, err
	}
	if tc.Name == "" {
		tc.Name = filepath.Base(path)
	}
	return tc, nil
}

func runCase(t *testing.T, caseDir string, tc testCase) {
	t.Helper()
	if tc.Fixture != "" {
		tc = materializeCaseFixture(t, tc)
	}

	testsDir := filepath.Dir(caseDir)
	policyPath := resolveCasePath(testsDir, tc.Policy)
	certsPath := resolveCasePath(testsDir, tc.Certs)
	crlPath := ""
	ocspPath := ""
	if tc.CRL != "" {
		crlPath = resolveCasePath(testsDir, tc.CRL)
	}
	if tc.OCSP != "" {
		ocspPath = resolveCasePath(testsDir, tc.OCSP)
	}
	var evalTime time.Time
	if tc.EvalTime != "" {
		parsed, err := time.Parse(time.RFC3339, tc.EvalTime)
		if err != nil {
			t.Fatalf("invalid eval_time %q: %v", tc.EvalTime, err)
		}
		evalTime = parsed
	}

	reg := operator.DefaultRegistry()
	p, err := policy.ParseFileWithRegistry(policyPath, reg)
	if err != nil {
		t.Fatalf("unexpected policy parse error: %v", err)
	}
	if len(tc.Rules) > 0 {
		p = selectPolicyRules(t, p, tc.Rules)
	}

	certs, err := cert.LoadCertificates(certsPath)
	if err != nil {
		t.Fatalf("unexpected cert load error: %v", err)
	}
	for _, issuer := range tc.Issuers {
		issuerCerts, err := cert.LoadCertificates(resolveCasePath(testsDir, issuer))
		if err != nil {
			t.Fatalf("unexpected issuer cert load error: %v", err)
		}
		certs = append(certs, issuerCerts...)
	}

	chain, err := cert.BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected chain error: %v", err)
	}

	results := make([]policy.Result, 0, len(chain))
	ctxOpts := make([]operator.ContextOption, 0)
	if tc.ApplicationPurpose != "" {
		ctxOpts = append(ctxOpts, operator.WithApplicationPurpose(tc.ApplicationPurpose))
	}

	// Load CRLs once
	var crlInfos []*crl.Info
	if crlPath != "" {
		crlInfos, err = crl.GetCRLs(crlPath)
		if err != nil {
			if tc.WantCRLLoadError {
				return
			}
			t.Fatalf("unexpected CRL load error: %v", err)
		}
		if tc.WantCRLLoadError {
			t.Fatal("expected generated CRL to be rejected during loading")
		}
		ctxOpts = append(ctxOpts, operator.WithCRLs(crlInfos))
	}

	// Load OCSP once
	if ocspPath != "" {
		ocsps, err := ocsp.GetOCSPs(ocspPath)
		if err != nil {
			t.Fatalf("unexpected OCSP load error: %v", err)
		}
		ctxOpts = append(ctxOpts, operator.WithOCSPs(ocsps))
	}

	var embeddedCRL *crl.Info
	var embeddedCRLIssuers []*x509.Certificate
	for _, crlInfo := range crlInfos {
		if crlInfo != nil && crlInfo.CRL != nil {
			embeddedCRL = crlInfo
			embeddedCRLIssuers = cert.CertsFromInfos(chain)
			break
		}
	}

	for _, c := range chain {
		tree := certzcrypto.BuildTree(c.Cert)
		if tc.ApplicationPurpose != "" {
			tree.Children["applicationPurpose"] = node.New(
				"applicationPurpose",
				tc.ApplicationPurpose,
			)
		}

		if embeddedCRL != nil {
			crlNode := crl.BuildTreeWithChain(embeddedCRL.CRL, embeddedCRLIssuers)
			if crlNode != nil {
				tree.Children["crl"] = crlNode
			}
		}

		certOpts := append([]operator.ContextOption(nil), ctxOpts...)
		if embeddedCRL != nil {
			certOpts = append(certOpts,
				operator.WithCurrentCRL(embeddedCRL),
				operator.WithCRLIssuers(embeddedCRLIssuers),
			)
		}
		ctx := operator.NewEvaluationContext(tree, c, chain, certOpts...)
		if !evalTime.IsZero() {
			ctx.Now = evalTime
		}
		for _, candidate := range policy.ByCertificate([]policy.Policy{p}, c.Cert) {
			results = append(results, policy.Evaluate(candidate, tree, reg, ctx))
		}
	}

	for _, crlInfo := range crlInfos {
		if crlInfo == nil || crlInfo.CRL == nil {
			continue
		}
		issuerPool := cert.CertsFromInfos(chain)
		tree := crl.BuildTreeWithChain(crlInfo.CRL, issuerPool)
		ctx := operator.NewEvaluationContext(
			tree,
			&cert.Info{Type: "crl", FilePath: crlInfo.FilePath, Source: crlInfo.Source},
			chain,
			operator.WithCRLs(crlInfos),
			operator.WithCurrentCRL(crlInfo),
			operator.WithCRLIssuers(issuerPool),
		)
		if !evalTime.IsZero() {
			ctx.Now = evalTime
		}
		for _, candidate := range policy.ByCRL([]policy.Policy{p}, crlInfo.CRL) {
			results = append(results, policy.Evaluate(candidate, tree, reg, ctx))
		}
	}

	if len(results) != len(tc.Expected) {
		t.Fatalf("expected %d results, got %d", len(tc.Expected), len(results))
	}

	for _, res := range results {
		counts := countVerdicts(res.Results)
		want, ok := tc.Expected[res.CertType]
		if !ok {
			t.Fatalf("unexpected cert type %q", res.CertType)
		}
		if counts != want {
			t.Fatalf("cert %s: expected %+v, got %+v", res.CertType, want, counts)
		}
	}
}

func countVerdicts(results []rule.Result) counts {
	var c counts
	for _, r := range results {
		switch r.Verdict {
		case rule.VerdictPass:
			c.Pass++
		case rule.VerdictFail:
			c.Fail++
		case rule.VerdictSkip:
			c.Skip++
		}
	}
	return c
}

func resolveCasePath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func selectPolicyRules(t *testing.T, p policy.Policy, ruleIDs []string) policy.Policy {
	t.Helper()

	wanted := make(map[string]struct{}, len(ruleIDs))
	for _, id := range ruleIDs {
		wanted[id] = struct{}{}
	}

	filtered := make([]rule.Rule, 0, len(ruleIDs))
	for _, candidate := range p.Rules {
		if _, ok := wanted[candidate.ID]; !ok {
			continue
		}
		filtered = append(filtered, candidate)
		delete(wanted, candidate.ID)
	}
	if len(wanted) > 0 {
		for id := range wanted {
			t.Errorf("policy %q does not contain selected rule %q", p.ID, id)
		}
		t.FailNow()
	}
	p.Rules = filtered
	return p
}

func materializeCaseFixture(t *testing.T, tc testCase) testCase {
	t.Helper()
	dir := t.TempDir()

	switch tc.Fixture {
	case "certificate-algorithm-mismatch":
		_, _, der := makeIntegrationCertificate(t, nil)
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE", replaceOuterSignatureAlgorithm(t, der))
	case "crl-algorithm-mismatch":
		key, issuer, issuerDER := makeIntegrationCertificate(t, nil)
		tc.Certs = writePEMFixture(t, dir, "issuer.pem", "CERTIFICATE", issuerDER)
		crlDER := makeIntegrationCRL(t, issuer, key)
		tc.CRL = writePEMFixture(t, dir, "list.pem", "X509 CRL", replaceOuterSignatureAlgorithm(t, crlDER))
	case "crl-entry-critical-extension":
		key, issuer, issuerDER := makeIntegrationCertificate(t, nil)
		tc.Certs = writePEMFixture(t, dir, "issuer.pem", "CERTIFICATE", issuerDER)
		crlDER, err := cryptox509.CreateRevocationList(rand.Reader, &cryptox509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: time.Date(2026, 7, 18, 11, 0, 0, 0, time.UTC),
			NextUpdate: time.Date(2026, 7, 19, 11, 0, 0, 0, time.UTC),
			RevokedCertificateEntries: []cryptox509.RevocationListEntry{{
				SerialNumber:   big.NewInt(2),
				RevocationTime: time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC),
				ExtraExtensions: []cryptopkix.Extension{{
					Id:       stdasn1.ObjectIdentifier{1, 2, 3, 4, 5},
					Critical: true,
					Value:    []byte{0x05, 0x00},
				}},
			}},
		}, issuer, key)
		if err != nil {
			t.Fatalf("create CRL with critical entry extension: %v", err)
		}
		tc.CRL = writePEMFixture(t, dir, "list.pem", "X509 CRL", crlDER)
	case "certificate-empty-key-usage":
		_, _, der := makeIntegrationCertificate(t, func(template *cryptox509.Certificate) {
			template.KeyUsage = 0
			template.ExtraExtensions = []cryptopkix.Extension{{
				Id:       stdasn1.ObjectIdentifier{2, 5, 29, 15},
				Critical: true,
				Value:    []byte{0x03, 0x01, 0x00},
			}}
		})
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE", der)
	case "certificate-empty-general-names":
		_, _, der := makeIntegrationCertificate(t, func(template *cryptox509.Certificate) {
			template.IsCA = false
			template.KeyUsage = cryptox509.KeyUsageDigitalSignature
			template.SubjectKeyId = nil
			template.ExtraExtensions = []cryptopkix.Extension{{
				Id:    stdasn1.ObjectIdentifier{2, 5, 29, 17},
				Value: []byte{0x30, 0x00},
			}}
		})
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE", der)
	case "certificate-validity-boundary":
		boundary := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
		_, _, der := makeIntegrationCertificate(t, func(template *cryptox509.Certificate) {
			template.NotBefore = boundary
			template.NotAfter = boundary
		})
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE", der)
		tc.EvalTime = boundary.Format(time.RFC3339)
	case "certificate-validity-encoding-cutover":
		_, _, der := makeIntegrationCertificate(t, func(template *cryptox509.Certificate) {
			template.NotBefore = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)
			template.NotAfter = time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)
		})
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE", der)
	case "certificate-serial-leading-sign-octet":
		_, _, der := makeIntegrationCertificate(t, nil)
		der = rewriteIntegrationTBSCertificate(t, der, func(fields [][]byte) [][]byte {
			if len(fields) < 2 || len(fields[1]) == 0 || fields[1][0] != 0x02 {
				t.Fatalf("TBSCertificate serialNumber field is missing")
			}

			magnitude := append([]byte{0x80}, make([]byte, 19)...)
			serialDER, err := stdasn1.Marshal(new(big.Int).SetBytes(magnitude))
			if err != nil {
				t.Fatalf("marshal integration serial number: %v", err)
			}
			fields[1] = serialDER
			return fields
		})
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE", der)
	case "certificate-zero-bit-issuer-unique-id":
		_, _, der := makeIntegrationCertificate(t, nil)
		der = rewriteIntegrationTBSCertificate(t, der, func(fields [][]byte) [][]byte {
			// issuerUniqueID is [1] IMPLICIT BIT STRING. A content octet of zero
			// denotes a present identifier containing zero bits.
			issuerUniqueID := []byte{0x81, 0x01, 0x00}
			insertAt := len(fields)
			for i, field := range fields {
				if len(field) > 0 && field[0] == 0xa3 {
					insertAt = i
					break
				}
			}
			fields = append(fields, nil)
			copy(fields[insertAt+1:], fields[insertAt:])
			fields[insertAt] = issuerUniqueID
			return fields
		})
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE", der)
	case "certificate-ian-second-invalid-dns-label":
		issuerAlternativeName, err := oid.Parse(oid.IssuerAlternativeName)
		if err != nil {
			t.Fatalf("parse issuer alternative name OID: %v", err)
		}
		validName := encodeIntegrationElement(0x82, []byte("valid.example"))
		invalidName := encodeIntegrationElement(0x82, []byte{'i', 'n', 'v', 'a', 'l', 'i', 'd', 0xe9, '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'})
		_, _, der := makeIntegrationCertificate(t, func(template *cryptox509.Certificate) {
			template.IsCA = false
			template.KeyUsage = cryptox509.KeyUsageDigitalSignature
			template.SubjectKeyId = nil
			template.ExtraExtensions = []cryptopkix.Extension{{
				Id:    issuerAlternativeName,
				Value: derasn1.EncodeSequence(append(validName, invalidName...)),
			}}
		})
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE", der)
	case "certificate-san-second-non-ia5-name":
		_, _, der := makeIntegrationCertificate(t, func(template *cryptox509.Certificate) {
			template.IsCA = false
			template.KeyUsage = cryptox509.KeyUsageDigitalSignature
			template.SubjectKeyId = nil
			template.DNSNames = []string{"valid.example", "nonascii.example"}
		})
		encodedName := []byte("nonascii.example")
		nameAt := bytes.Index(der, encodedName)
		if nameAt < 0 {
			t.Fatal("generated SAN name not found in certificate DER")
		}
		der[nameAt] = 0xe9
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE", der)
	case "crl-missing-required-fields":
		key, issuer, issuerDER := makeIntegrationCertificate(t, nil)
		tc.Certs = writePEMFixture(t, dir, "issuer.pem", "CERTIFICATE", issuerDER)
		crlDER := removeCRLRequiredFields(t, makeIntegrationCRL(t, issuer, key))
		tc.CRL = writePEMFixture(t, dir, "list.pem", "X509 CRL", crlDER)
	case "crl-dn-noncanonical-order":
		key, issuer, issuerDER := makeIntegrationCertificate(t, func(template *cryptox509.Certificate) {
			template.RawSubject = makeIntegrationNonCanonicalName(t)
		})
		tc.Certs = writePEMFixture(t, dir, "issuer.pem", "CERTIFICATE", issuerDER)
		tc.CRL = writePEMFixture(t, dir, "list.pem", "X509 CRL", makeIntegrationCRL(t, issuer, key))
	case "certificate-dn-second-common-name-too-long":
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE",
			makeIntegrationLeafWithSubject(t, makeIntegrationName(t,
				integrationNameAttribute{identifier: oid.AttributeCommonName, tag: integrationUTF8StringTag, value: "first"},
				integrationNameAttribute{identifier: oid.AttributeCommonName, tag: integrationUTF8StringTag, value: strings.Repeat("x", 65)},
			)),
		)
	case "certificate-dn-projected-attributes":
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE",
			makeIntegrationLeafWithSubject(t, makeIntegrationName(t,
				integrationNameAttribute{identifier: oid.AttributeGivenName, tag: integrationUTF8StringTag, value: strings.Repeat("g", 65)},
				integrationNameAttribute{identifier: oid.AttributeSurname, tag: integrationUTF8StringTag, value: strings.Repeat("s", 65)},
				integrationNameAttribute{identifier: oid.AttributeEmailAddress, tag: integrationIA5StringTag, value: "not-an-email-address"},
				integrationNameAttribute{identifier: oid.AttributeDomainComponent, tag: integrationIA5StringTag, value: strings.Repeat("d", 64)},
			)),
		)
	case "certificate-country-name-utf8string":
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE",
			makeIntegrationLeafWithSubject(t, makeIntegrationName(t,
				integrationNameAttribute{identifier: oid.AttributeCountryName, tag: integrationUTF8StringTag, value: "DE"},
			)),
		)
	case "certificate-dn-noncanonical-order":
		tc.Certs = writePEMFixture(t, dir, "certificate.pem", "CERTIFICATE",
			makeIntegrationLeafWithSubject(t, makeIntegrationNonCanonicalName(t)),
		)
	default:
		t.Fatalf("unknown generated fixture %q", tc.Fixture)
	}

	return tc
}

func makeIntegrationCertificate(
	t *testing.T,
	mutate func(*cryptox509.Certificate),
) (*rsa.PrivateKey, *cryptox509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cryptopkix.Name{CommonName: "integration-generated"},
		NotBefore:             time.Date(2026, 7, 18, 11, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 7, 18, 13, 0, 0, 0, time.UTC),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03},
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := cryptox509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	issuer, err := cryptox509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse issuer certificate: %v", err)
	}
	return key, issuer, der
}

const (
	integrationUTF8StringTag = 12
	integrationIA5StringTag  = 22
)

type integrationNameAttribute struct {
	identifier string
	tag        int
	value      string
}

func makeIntegrationLeafWithSubject(t *testing.T, rawSubject []byte) []byte {
	t.Helper()
	_, _, der := makeIntegrationCertificate(t, func(template *cryptox509.Certificate) {
		template.RawSubject = rawSubject
		template.IsCA = false
		template.KeyUsage = cryptox509.KeyUsageDigitalSignature
		template.SubjectKeyId = nil
	})
	return der
}

func makeIntegrationName(t *testing.T, attributes ...integrationNameAttribute) []byte {
	t.Helper()
	rdns := make(cryptopkix.RDNSequence, 0, len(attributes))
	for _, attribute := range attributes {
		identifier, err := oid.Parse(attribute.identifier)
		if err != nil {
			t.Fatalf("parse name attribute OID %q: %v", attribute.identifier, err)
		}
		rdns = append(rdns, cryptopkix.RelativeDistinguishedNameSET{
			{
				Type: identifier,
				Value: stdasn1.RawValue{
					Class: stdasn1.ClassUniversal,
					Tag:   attribute.tag,
					Bytes: []byte(attribute.value),
				},
			},
		})
	}
	der, err := stdasn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("marshal integration distinguished name: %v", err)
	}
	return der
}

func makeIntegrationNonCanonicalName(t *testing.T) []byte {
	t.Helper()
	first := makeIntegrationNameAttribute(t, integrationNameAttribute{
		identifier: oid.AttributeCommonName,
		tag:        integrationUTF8StringTag,
		value:      "subject",
	})
	second := makeIntegrationNameAttribute(t, integrationNameAttribute{
		identifier: oid.AttributeOrganizationName,
		tag:        integrationUTF8StringTag,
		value:      "subject",
	})
	if bytes.Compare(first, second) < 0 {
		first, second = second, first
	}
	rdn := encodeIntegrationElement(0x31, append(first, second...))
	return derasn1.EncodeSequence(rdn)
}

func makeIntegrationNameAttribute(t *testing.T, attribute integrationNameAttribute) []byte {
	t.Helper()
	identifier, err := oid.Parse(attribute.identifier)
	if err != nil {
		t.Fatalf("parse name attribute OID %q: %v", attribute.identifier, err)
	}
	der, err := stdasn1.Marshal(cryptopkix.AttributeTypeAndValue{
		Type: identifier,
		Value: stdasn1.RawValue{
			Class: stdasn1.ClassUniversal,
			Tag:   attribute.tag,
			Bytes: []byte(attribute.value),
		},
	})
	if err != nil {
		t.Fatalf("marshal integration name attribute: %v", err)
	}
	return der
}

func encodeIntegrationElement(tag byte, content []byte) []byte {
	if len(content) >= 128 {
		panic("integration DER helper only supports short lengths")
	}
	return append([]byte{tag, byte(len(content))}, content...)
}

func makeIntegrationCRL(
	t *testing.T,
	issuer *cryptox509.Certificate,
	key *rsa.PrivateKey,
) []byte {
	t.Helper()
	der, err := cryptox509.CreateRevocationList(rand.Reader, &cryptox509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Date(2026, 7, 18, 11, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2026, 7, 19, 11, 0, 0, 0, time.UTC),
	}, issuer, key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return der
}

func writePEMFixture(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write generated fixture: %v", err)
	}
	return path
}

type integrationSignedEnvelope struct {
	TBS       stdasn1.RawValue
	Algorithm stdasn1.RawValue
	Signature stdasn1.RawValue
}

func decodeIntegrationSignedEnvelope(t *testing.T, der []byte) integrationSignedEnvelope {
	t.Helper()
	var envelope integrationSignedEnvelope
	if rest, err := stdasn1.Unmarshal(der, &envelope); err != nil || len(rest) != 0 {
		t.Fatalf("decode signed envelope: rest=%x err=%v", rest, err)
	}
	return envelope
}

func replaceOuterSignatureAlgorithm(t *testing.T, der []byte) []byte {
	t.Helper()
	envelope := decodeIntegrationSignedEnvelope(t, der)
	var outer struct {
		Algorithm  stdasn1.ObjectIdentifier
		Parameters stdasn1.RawValue `asn1:"optional"`
	}
	if rest, err := stdasn1.Unmarshal(envelope.Algorithm.FullBytes, &outer); err != nil || len(rest) != 0 {
		t.Fatalf("decode outer AlgorithmIdentifier: rest=%x err=%v", rest, err)
	}
	outer.Algorithm = stdasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12} // sha384WithRSAEncryption
	outerDER, err := stdasn1.Marshal(outer)
	if err != nil {
		t.Fatalf("encode mismatched outer AlgorithmIdentifier: %v", err)
	}
	content := append([]byte(nil), envelope.TBS.FullBytes...)
	content = append(content, outerDER...)
	content = append(content, envelope.Signature.FullBytes...)
	return derasn1.EncodeSequence(content)
}

func rewriteIntegrationTBSCertificate(
	t *testing.T,
	der []byte,
	rewrite func([][]byte) [][]byte,
) []byte {
	t.Helper()
	envelope := decodeIntegrationSignedEnvelope(t, der)

	fields := rewrite(splitIntegrationDERElements(t, envelope.TBS.Bytes))
	tbsContent := bytes.Join(fields, nil)
	content := append([]byte(nil), derasn1.EncodeSequence(tbsContent)...)
	content = append(content, envelope.Algorithm.FullBytes...)
	content = append(content, envelope.Signature.FullBytes...)
	return derasn1.EncodeSequence(content)
}

func splitIntegrationDERElements(t *testing.T, content []byte) [][]byte {
	t.Helper()
	var elements [][]byte
	for len(content) > 0 {
		var element stdasn1.RawValue
		rest, err := stdasn1.Unmarshal(content, &element)
		if err != nil {
			t.Fatalf("decode TBSCertificate field: %v", err)
		}
		consumed := len(content) - len(rest)
		if consumed == 0 {
			t.Fatal("decode TBSCertificate field made no progress")
		}
		elements = append(elements, append([]byte(nil), content[:consumed]...))
		content = rest
	}
	return elements
}

func removeCRLRequiredFields(t *testing.T, der []byte) []byte {
	t.Helper()
	envelope := decodeIntegrationSignedEnvelope(t, der)

	var tbs struct {
		Raw                 stdasn1.RawContent
		Version             int `asn1:"optional,default:0"`
		Signature           cryptopkix.AlgorithmIdentifier
		Issuer              stdasn1.RawValue
		ThisUpdate          time.Time
		NextUpdate          time.Time                       `asn1:"optional"`
		RevokedCertificates []cryptopkix.RevokedCertificate `asn1:"optional"`
		Extensions          []cryptopkix.Extension          `asn1:"tag:0,optional,explicit"`
	}
	if rest, err := stdasn1.Unmarshal(envelope.TBS.FullBytes, &tbs); err != nil || len(rest) != 0 {
		t.Fatalf("decode TBSCertList: rest=%x err=%v", rest, err)
	}
	tbs.Raw = nil
	tbs.NextUpdate = time.Time{}
	tbs.Extensions = nil
	tbsDER, err := stdasn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("encode TBSCertList without required fields: %v", err)
	}

	content := append([]byte(nil), tbsDER...)
	content = append(content, envelope.Algorithm.FullBytes...)
	content = append(content, envelope.Signature.FullBytes...)
	return derasn1.EncodeSequence(content)
}
