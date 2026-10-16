package node_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/certnode"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/crlnode"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/ocspnode"
	"github.com/cavoq/PCL/internal/testfiles"
)

// Every path listed for a projected tree must resolve back to the same node,
// so policy authors can copy any listed path into a rule target.
func TestPathsResolveToTheirNodes(t *testing.T) {
	var trees []*node.Node
	for _, dir := range []string{testfiles.Certs(), testfiles.CertTestdata(), testfiles.CRLTestdata()} {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !slices.Contains([]string{".pem", ".der", ".crt", ".cer"}, filepath.Ext(path)) {
				return nil
			}
			certificates, loadErr := cert.LoadCertificates(path, nil)
			if loadErr != nil {
				return nil
			}
			for _, certificate := range certificates {
				trees = append(trees, certnode.BuildTree(certificate.Cert))
			}
			return nil
		})
	}
	for _, dir := range []string{testfiles.CRLs(), testfiles.CRLTestdata()} {
		lists, err := crl.GetCRLs(dir, nil)
		if err != nil {
			t.Fatalf("GetCRLs(%s): %v", dir, err)
		}
		for _, list := range lists {
			trees = append(trees, crlnode.BuildTree(list.CRL))
		}
	}
	responses, err := ocsp.GetOCSPs(testfiles.OCSPs(), nil)
	if err != nil {
		t.Fatalf("GetOCSPs: %v", err)
	}
	for _, response := range responses {
		trees = append(trees, ocspnode.BuildTree(response.Response))
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
