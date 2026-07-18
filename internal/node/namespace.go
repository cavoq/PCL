package node

import "strings"

const (
	CertificateNamespace = "certificate"
	CRLNamespace         = "crl"
	OCSPNamespace        = "ocsp"
	TSTNamespace         = "tst"
	SCTNamespace         = "sct"
	AttrCertNamespace    = "attrCert"
)

// InputNamespace returns the recognized input namespace at the start of a
// node path. Unqualified policy targets are not input namespaces.
func InputNamespace(path string) (string, bool) {
	namespace := path
	if dot := strings.IndexByte(path, '.'); dot >= 0 {
		namespace = path[:dot]
	}

	switch namespace {
	case CertificateNamespace,
		CRLNamespace,
		OCSPNamespace,
		TSTNamespace,
		SCTNamespace,
		AttrCertNamespace:
		return namespace, true
	default:
		return "", false
	}
}

// HasInputNamespace reports whether root contains the input addressed by
// path. A root may itself be that input or embed it as a direct child.
// Unqualified targets address the current tree and are therefore available.
func HasInputNamespace(root *Node, path string) bool {
	namespace, qualified := InputNamespace(path)
	if !qualified {
		return true
	}
	if root == nil {
		return false
	}
	if root.Name == namespace {
		return true
	}
	_, ok := root.Children[namespace]
	return ok
}
