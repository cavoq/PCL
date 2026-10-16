// Package testfiles locates the repository's shared test files, so tests and
// fixture generators do not depend on their own directory depth or working
// directory. The repository layout is named only here: when a directory
// moves, change its function below.
//
// Only tests and development tools may import this package; the pcl binary
// must not depend on the source tree.
package testfiles

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// Root returns the absolute path of the repository root, the nearest
// directory above this source file, or else above the working directory,
// that holds go.mod. It panics when there is none.
var Root = sync.OnceValue(func() string {
	var starts []string
	if _, here, _, ok := runtime.Caller(0); ok && filepath.IsAbs(here) {
		starts = append(starts, filepath.Dir(here))
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	for _, dir := range starts {
		if root, ok := moduleRoot(dir); ok {
			return root
		}
	}
	panic("testfiles: no go.mod above the source or working directory")
})

func moduleRoot(dir string) (string, bool) {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// Path joins elem to the repository root.
func Path(elem ...string) string {
	return filepath.Join(append([]string{Root()}, elem...)...)
}

// Tests joins elem to the tests directory, the root of the generated
// fixtures and the integration tests.
func Tests(elem ...string) string { return under([]string{"tests"}, elem) }

// Certs joins elem to the generated certificate fixtures.
func Certs(elem ...string) string { return under([]string{"tests", "certs"}, elem) }

// CRLs joins elem to the generated CRL fixtures.
func CRLs(elem ...string) string { return under([]string{"tests", "crls"}, elem) }

// OCSPs joins elem to the generated OCSP response fixtures.
func OCSPs(elem ...string) string { return under([]string{"tests", "ocsps"}, elem) }

// Policies joins elem to the policies written for tests.
func Policies(elem ...string) string { return under([]string{"tests", "policies"}, elem) }

// PolicySuites joins elem to the policy test suites.
func PolicySuites(elem ...string) string { return under([]string{"tests", "policy-suites"}, elem) }

// PKITS joins elem to the vendored NIST PKITS data.
func PKITS(elem ...string) string { return under([]string{"tests", "pkits"}, elem) }

// PKITSCerts joins elem to the PKITS certificates.
func PKITSCerts(elem ...string) string { return under([]string{"tests", "pkits", "certs"}, elem) }

// Limbo joins elem to the x509-limbo test data.
func Limbo(elem ...string) string { return under([]string{"tests", "limbo"}, elem) }

// PolicyPacks joins elem to the shipped policy packs.
func PolicyPacks(elem ...string) string { return under([]string{"policies"}, elem) }

// Schema returns the committed policy JSON Schema.
func Schema() string { return Path("schemas", "policy.schema.json") }

// CertTestdata joins elem to the cert package's testdata.
func CertTestdata(elem ...string) string {
	return under([]string{"internal", "cert", "testdata"}, elem)
}

// CRLTestdata joins elem to the crl package's testdata.
func CRLTestdata(elem ...string) string {
	return under([]string{"internal", "crl", "testdata"}, elem)
}

func under(dir, elem []string) string {
	return Path(append(dir, elem...)...)
}
