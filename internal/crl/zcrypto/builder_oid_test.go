package zcrypto

import "testing"

func TestBuildTree_CRLOIDs(t *testing.T) {
	crl := loadTestCRL(t, "test.crl")
	tree := BuildTree(crl)

	tests := []struct {
		path string
		want string
	}{
		{
			path: "crl.signatureAlgorithm.oid",
			want: "1.2.840.113549.1.1.11",
		},
		{
			path: "crl.tbsSignatureAlgorithm.oid",
			want: "1.2.840.113549.1.1.11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			gotNode, ok := tree.Resolve(tt.path)
			if !ok {
				t.Fatalf("expected path %q to exist", tt.path)
			}

			got, ok := gotNode.Value.(string)
			if !ok {
				t.Fatalf("expected %q to be a string, got %T", tt.path, gotNode.Value)
			}
			if got != tt.want {
				t.Fatalf("%q: got %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
