package httpfetch

import (
	"slices"
	"testing"
)

func TestHTTPURLs(t *testing.T) {
	supported, err := HTTPURLs([]string{"ldap://a.example/", "HTTPS://b.example/ca.crt", "http://c.example/ca.crt"}, "CA Issuers")
	if err != nil {
		t.Fatalf("HTTPURLs: %v", err)
	}
	if !slices.Equal(supported, []string{"HTTPS://b.example/ca.crt", "http://c.example/ca.crt"}) {
		t.Fatalf("supported = %v", supported)
	}

	if supported, err := HTTPURLs(nil, "CA Issuers"); err != nil || supported != nil {
		t.Fatalf("HTTPURLs(nil) = %v, %v; want nil, nil", supported, err)
	}

	_, err = HTTPURLs([]string{"ftp://a.example/ca.crt", "ldap://b.example/", "%zz"}, "CA Issuers")
	want := "only ftp://, ldap:// CA Issuers URLs (ftp://a.example/ca.crt, ldap://b.example/, %zz); FTP and LDAP retrieval is not supported"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestHTTPURLsWithoutScheme(t *testing.T) {
	_, err := HTTPURLs([]string{"directory.example/ca.crt"}, "CA Issuers")
	want := "only non-HTTP(S) CA Issuers URLs (directory.example/ca.crt); non-HTTP(S) retrieval is not supported"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}
