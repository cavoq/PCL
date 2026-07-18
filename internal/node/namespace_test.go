package node

import "testing"

func TestInputNamespace(t *testing.T) {
	tests := []struct {
		path      string
		want      string
		qualified bool
	}{
		{path: "certificate.validity.notAfter", want: CertificateNamespace, qualified: true},
		{path: "crl", want: CRLNamespace, qualified: true},
		{path: "ocsp.status", want: OCSPNamespace, qualified: true},
		{path: "custom.value"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, qualified := InputNamespace(tt.path)
			if got != tt.want || qualified != tt.qualified {
				t.Fatalf("InputNamespace(%q) = (%q, %v), want (%q, %v)", tt.path, got, qualified, tt.want, tt.qualified)
			}
		})
	}
}

func TestHasInputNamespace(t *testing.T) {
	root := New(CertificateNamespace, nil)
	root.Children[CRLNamespace] = New(CRLNamespace, nil)

	if !HasInputNamespace(root, "certificate.subject") {
		t.Fatal("root namespace should be available")
	}
	if !HasInputNamespace(root, "crl.nextUpdate") {
		t.Fatal("embedded namespace should be available")
	}
	if HasInputNamespace(root, "ocsp.status") {
		t.Fatal("missing input namespace should not be available")
	}
	if !HasInputNamespace(root, "custom.value") {
		t.Fatal("unqualified target should address the current tree")
	}
	if HasInputNamespace(nil, "certificate.subject") {
		t.Fatal("qualified target cannot be available on a nil root")
	}
}
