package testfiles

import (
	"os"
	"testing"
)

// TestDirectoriesExist fails when the layout changes without this package.
func TestDirectoriesExist(t *testing.T) {
	for _, path := range []string{
		Path("go.mod"), Tests(), Certs(), CRLs(), OCSPs(), Policies(), PolicySuites(),
		PKITS(), PKITSCerts(), Limbo(), PolicyPacks(), Schema(), CertTestdata(), CRLTestdata(),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Error(err)
		}
	}
}
