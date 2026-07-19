package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
	"github.com/zmap/zcrypto/x509"
)

func TestCertificateProfileOperatorNames(t *testing.T) {
	tests := []struct {
		operator Operator
		want     string
	}{
		{operator: ApplicationPurposeValid{}, want: "applicationPurposeValid"},
		{operator: AnyExtendedKeyUsageNotCritical{}, want: "anyExtendedKeyUsageNotCritical"},
		{operator: BasicConstraintsDependenciesValid{}, want: "basicConstraintsDependenciesValid"},
		{operator: KeyUsageDependenciesValid{}, want: "keyUsageDependenciesValid"},
		{operator: NameConstraintsDependenciesValid{}, want: "nameConstraintsDependenciesValid"},
		{operator: NameConstraintsDistancesValid{}, want: "nameConstraintsDistancesValid"},
		{operator: CRLDistributionPointsDependenciesValid{}, want: "crlDistributionPointsDependenciesValid"},
		{operator: PolicyMappingsDependenciesValid{}, want: "policyMappingsDependenciesValid"},
		{operator: PolicyMappingsIssuerPoliciesPresent{}, want: "policyMappingsIssuerPoliciesPresent"},
		{operator: PolicyConstraintsDependenciesValid{}, want: "policyConstraintsDependenciesValid"},
		{operator: InhibitAnyPolicyDependenciesValid{}, want: "inhibitAnyPolicyDependenciesValid"},
	}

	for _, test := range tests {
		if got := test.operator.Name(); got != test.want {
			t.Errorf("operator name = %q, want %q", got, test.want)
		}
	}
}

func TestApplicationPurposeValidDelegatesContextPurpose(t *testing.T) {
	certificate := &cert.Info{Cert: &x509.Certificate{}}
	ctx := NewEvaluationContext(
		node.New("certificate", nil),
		certificate,
		[]*cert.Info{certificate},
		WithApplicationPurpose("serverAuth"),
	)

	got, err := (ApplicationPurposeValid{}).Evaluate(nil, ctx, nil)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !got {
		t.Fatal("operator did not delegate the context application purpose")
	}
	if ctx.ApplicationPurpose != "serverAuth" {
		t.Fatalf("ApplicationPurpose = %q, want serverAuth", ctx.ApplicationPurpose)
	}
}

func TestCertificateProfileOperatorsRejectMissingCertificate(t *testing.T) {
	operators := []Operator{
		ApplicationPurposeValid{},
		AnyExtendedKeyUsageNotCritical{},
		BasicConstraintsDependenciesValid{},
		KeyUsageDependenciesValid{},
		NameConstraintsDependenciesValid{},
		NameConstraintsDistancesValid{},
		CRLDistributionPointsDependenciesValid{},
		PolicyMappingsDependenciesValid{},
		PolicyMappingsIssuerPoliciesPresent{},
		PolicyConstraintsDependenciesValid{},
		InhibitAnyPolicyDependenciesValid{},
	}
	for _, candidate := range operators {
		got, err := candidate.Evaluate(nil, nil, nil)
		if err != nil {
			t.Errorf("%s Evaluate() error = %v", candidate.Name(), err)
		}
		if got {
			t.Errorf("%s accepted a missing certificate", candidate.Name())
		}
	}
}
