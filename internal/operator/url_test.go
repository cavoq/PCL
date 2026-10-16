package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestHTTPURL(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{"http://example.com/cps", true},
		{"https://example.com/cps?v=2#terms", true},
		{"HTTPS://example.com/cps", true},
		{"http://[2001:db8::1]:8080/cps", true},
		{"https://example.com/a%20b", true},
		{"", false},
		{"ftp://example.com/cps", false},
		{"/cps", false},
		{"//example.com/cps", false},
		{"http:cps", false},
		{"https:///cps", false},
		{"http://:80/cps", false},
		{"https://example.com/a b", false},
		{"https://example.com/\n", false},
		{"https://example.com/é", false},
		{"https://example.com/%zz", false},
		{"https://example.com:abc/cps", false},
		{"https://example.com/\\cps", false},
	} {
		t.Run(test.value, func(t *testing.T) {
			got, err := DefaultRegistry().Evaluate("httpURL", node.New("url", test.value), nil, nil)
			if err != nil || got != test.want {
				t.Fatalf("httpURL(%q) = %v, %v; want %v", test.value, got, err, test.want)
			}
		})
	}
	for _, n := range []*node.Node{nil, node.New("url", 3), collection("urls", "https://example.com")} {
		if got, err := (HTTPURL{}).Evaluate(n, nil, nil); got || err != nil {
			t.Fatalf("non-string target: %v, %v", got, err)
		}
	}
}
