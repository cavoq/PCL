package node_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	ocspzcrypto "github.com/cavoq/PCL/internal/ocsp/zcrypto"
)

// Every path listed for a projected tree must resolve back to the same node,
// so policy authors can copy any listed path into a rule target.
func TestPathsResolveToTheirNodes(t *testing.T) {
	var trees []*node.Node
	for _, dir := range []string{"../../tests/certs", "../cert/testdata", "../crl/testdata"} {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !slices.Contains([]string{".pem", ".der", ".crt", ".cer"}, filepath.Ext(path)) {
				return nil
			}
			certificates, loadErr := cert.LoadCertificates(path, nil)
			if loadErr != nil {
				return nil
			}
			for _, certificate := range certificates {
				trees = append(trees, certzcrypto.BuildTree(certificate.Cert))
			}
			return nil
		})
	}
	for _, dir := range []string{"../../tests/crls", "../crl/testdata"} {
		lists, err := crl.GetCRLs(dir, nil)
		if err != nil {
			t.Fatalf("GetCRLs(%s): %v", dir, err)
		}
		for _, list := range lists {
			trees = append(trees, crl.BuildTree(list.CRL))
		}
	}
	responses, err := ocsp.GetOCSPs("../../tests/ocsps", nil)
	if err != nil {
		t.Fatalf("GetOCSPs: %v", err)
	}
	for _, response := range responses {
		trees = append(trees, ocspzcrypto.BuildTree(response.Response))
	}
	if len(trees) < 30 {
		t.Fatalf("only %d fixture trees loaded", len(trees))
	}

	checked := 0
	for _, tree := range trees {
		for _, entry := range node.Paths(tree) {
			resolved, ok := tree.Resolve(entry.Path)
			if !ok || resolved != entry.Node {
				t.Errorf("%s does not resolve to its node", entry.Path)
			}
			checked++
		}
	}
	t.Logf("checked %d paths in %d trees", checked, len(trees))
}
