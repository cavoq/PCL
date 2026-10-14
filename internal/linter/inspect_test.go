package linter

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func inspectTestConfig() Config {
	certDir := filepath.Join("..", "..", "tests", "certs")
	return Config{
		CertPath:    filepath.Join(certDir, "leaf.pem"),
		IssuerPaths: []string{certDir},
	}
}

func TestInspectPrintsTreePerChainCertificate(t *testing.T) {
	var out bytes.Buffer
	if err := Inspect(inspectTestConfig(), InspectOptions{}, &out); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"# certificate (leaf) ",
		"# certificate (root) ",
		"├── subjectAltName: 1\n",
		"│   ├── dNSName\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("tree output does not contain %q", want)
		}
	}
}

func TestInspectPathsAreRuleTargets(t *testing.T) {
	cfg := inspectTestConfig()
	cfg.CRLPath = filepath.Join("..", "..", "tests", "crls", "revoked-leaf.crl")
	cfg.ApplicationPurpose = "serverAuth"

	var out bytes.Buffer
	if err := Inspect(cfg, InspectOptions{Paths: true}, &out); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"\ncertificate.subjectAltName.dNSName.0 = leaf.example.test (string)\n",
		"\ncertificate.applicationPurpose = serverAuth (string)\n",
		"\ncertificate.revocation.status = ",
		"\n# crl ",
		"\ncrl.crlNumber = 42 (string)\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("paths output does not contain %q", want)
		}
	}
}

func TestInspectJSONDocument(t *testing.T) {
	cfg := Config{OCSPPath: filepath.Join("..", "..", "tests", "ocsps", "good-leaf.ocsp"), OutputFmt: "json"}

	var out bytes.Buffer
	if err := Inspect(cfg, InspectOptions{Paths: true}, &out); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	var document []inspectedInput
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if len(document) == 0 || document[0].Input != "ocsp" || len(document[0].Paths) == 0 {
		t.Fatalf("document = %+v", document)
	}
	found := false
	for _, path := range document[0].Paths {
		if path.Path == "ocsp.nextUpdate" && path.Kind == "time" && path.Value == "2030-01-10T00:00:00Z" {
			found = true
		}
	}
	if !found {
		t.Fatal("ocsp.nextUpdate time path is missing")
	}
}

func TestInspectRequiresInput(t *testing.T) {
	err := Inspect(Config{IssuerPaths: []string{"issuer.pem"}}, InspectOptions{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no certificates, CRLs, or OCSP responses provided") {
		t.Fatalf("expected missing input error, got %v", err)
	}
}
