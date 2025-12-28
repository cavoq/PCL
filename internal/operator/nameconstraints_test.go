package operator

import (
	"net"
	"testing"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/cert"
)

func TestNameConstraintsValidName(t *testing.T) {
	op := NameConstraintsValid{}
	if op.Name() != "nameConstraintsValid" {
		t.Error("wrong name")
	}
}

func TestNameConstraintsValidNilContext(t *testing.T) {
	op := NameConstraintsValid{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil context should return false")
	}
}

func TestNameConstraintsValidNoChain(t *testing.T) {
	op := NameConstraintsValid{}
	ctx := &EvaluationContext{
		Cert:  &cert.Info{Cert: &x509.Certificate{}},
		Chain: nil,
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("no chain should return false")
	}
}

func TestNameConstraintsValidNoConstraints(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		DNSNames: []string{"example.com"},
	}
	caCert := &x509.Certificate{}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("no constraints should pass")
	}
}

func TestNameConstraintsValidDNSPermitted(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		DNSNames: []string{"foo.example.com"},
	}
	caCert := &x509.Certificate{
		PermittedDNSNames: []x509.GeneralSubtreeString{
			{Data: ".example.com"},
		},
	}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("DNS within permitted should pass")
	}
}

func TestNameConstraintsValidDNSNotPermitted(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		DNSNames: []string{"foo.other.com"},
	}
	caCert := &x509.Certificate{
		PermittedDNSNames: []x509.GeneralSubtreeString{
			{Data: ".example.com"},
		},
	}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("DNS outside permitted should fail")
	}
}

func TestNameConstraintsValidDNSExcluded(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		DNSNames: []string{"foo.bad.com"},
	}
	caCert := &x509.Certificate{
		ExcludedDNSNames: []x509.GeneralSubtreeString{
			{Data: ".bad.com"},
		},
	}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("DNS in excluded should fail")
	}
}

func TestNameConstraintsValidEmailPermitted(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		EmailAddresses: []string{"user@example.com"},
	}
	caCert := &x509.Certificate{
		PermittedEmailAddresses: []x509.GeneralSubtreeString{
			{Data: "example.com"},
		},
	}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("email within permitted should pass")
	}
}

func TestNameConstraintsValidEmailNotPermitted(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		EmailAddresses: []string{"user@other.com"},
	}
	caCert := &x509.Certificate{
		PermittedEmailAddresses: []x509.GeneralSubtreeString{
			{Data: "example.com"},
		},
	}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("email outside permitted should fail")
	}
}

func TestNameConstraintsValidIPPermitted(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		IPAddresses: []net.IP{net.ParseIP("192.168.1.100")},
	}
	_, ipnet, _ := net.ParseCIDR("192.168.0.0/16")
	caCert := &x509.Certificate{
		PermittedIPAddresses: []x509.GeneralSubtreeIP{
			{Data: *ipnet},
		},
	}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("IP within permitted should pass")
	}
}

func TestNameConstraintsValidIPNotPermitted(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
	}
	_, ipnet, _ := net.ParseCIDR("192.168.0.0/16")
	caCert := &x509.Certificate{
		PermittedIPAddresses: []x509.GeneralSubtreeIP{
			{Data: *ipnet},
		},
	}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("IP outside permitted should fail")
	}
}

func TestNameConstraintsValidIPExcluded(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		IPAddresses: []net.IP{net.ParseIP("192.168.1.100")},
	}
	_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
	caCert := &x509.Certificate{
		ExcludedIPAddresses: []x509.GeneralSubtreeIP{
			{Data: *ipnet},
		},
	}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("IP in excluded should fail")
	}
}

func TestNameConstraintsValidURIPermitted(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		URIs: []string{"https://foo.example.com/path"},
	}
	caCert := &x509.Certificate{
		PermittedURIs: []x509.GeneralSubtreeString{
			{Data: ".example.com"},
		},
	}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: caCert, Position: 1},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("URI within permitted should pass")
	}
}

func TestNameConstraintsValidMultipleCAConstraints(t *testing.T) {
	op := NameConstraintsValid{}
	leafCert := &x509.Certificate{
		DNSNames: []string{"foo.example.com"},
	}
	intermediateCert := &x509.Certificate{
		PermittedDNSNames: []x509.GeneralSubtreeString{
			{Data: ".example.com"},
		},
	}
	rootCert := &x509.Certificate{
		ExcludedDNSNames: []x509.GeneralSubtreeString{
			{Data: ".bad.com"},
		},
	}

	ctx := &EvaluationContext{
		Cert: &cert.Info{Cert: leafCert, Position: 0},
		Chain: []*cert.Info{
			{Cert: leafCert, Position: 0},
			{Cert: intermediateCert, Position: 1},
			{Cert: rootCert, Position: 2},
		},
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("should pass with multiple CA constraints")
	}
}

func TestMatchesDNS(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		want       bool
	}{
		{"example.com", ".example.com", false},
		{"foo.example.com", ".example.com", true},
		{"example.com", "example.com", true},
		{"foo.example.com", "example.com", true},
		{"other.com", ".example.com", false},
		{"foo.bar.example.com", ".example.com", true},
	}

	for _, tt := range tests {
		got := matchesDNS(tt.name, tt.constraint)
		if got != tt.want {
			t.Errorf("matchesDNS(%q, %q) = %v, want %v", tt.name, tt.constraint, got, tt.want)
		}
	}
}
