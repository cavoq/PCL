package policy

import (
	"slices"
	"strings"

	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
)

// RuleAppliesToInput reports whether a rule should run for the current evaluation
// input (cert, crl, ocsp). Mixed policies (RFC5280, RFC4055) include both
// certificate.* and crl.* rules; only the matching subset is evaluated per pass.
func RuleAppliesToInput(r rule.Rule, inputType string, ctx *operator.EvaluationContext) bool {
	if len(r.CertType) > 0 {
		if ctx == nil || ctx.Cert == nil {
			return false
		}
		return slices.Contains(r.CertType, ctx.Cert.Type)
	}

	targetInput := inferInputFromTarget(r.Target)
	whenInput := ""
	if r.When != nil {
		whenInput = inferInputFromTarget(r.When.Target)
	}

	// Unqualified targets (e.g. custom nodes in unit tests) run on every input.
	if targetInput == "" && whenInput == "" {
		return true
	}

	switch inputType {
	case InputCRL:
		// Dedicated CRL pass (evaluator.CRL): only crl.* targets, never certificate.*.
		return targetInput == InputCRL
	case InputCert:
		if targetInput == InputCert {
			return true
		}
		// Chain evaluation may attach a crl subtree (see tests/integration_test.go).
		if targetInput == InputCRL || whenInput == InputCRL {
			return true
		}
		return false
	case InputOCSP:
		return targetInput == InputOCSP || whenInput == InputOCSP
	default:
		return true
	}
}

func inferInputFromTarget(target string) string {
	switch {
	case target == "certificate" || strings.HasPrefix(target, "certificate."):
		return InputCert
	case target == "crl" || strings.HasPrefix(target, "crl."):
		return InputCRL
	case target == "ocsp" || strings.HasPrefix(target, "ocsp."):
		return InputOCSP
	default:
		return ""
	}
}

func inputTypeFromContext(ctx *operator.EvaluationContext) string {
	if ctx == nil || ctx.Cert == nil {
		return InputCert
	}
	switch ctx.Cert.Type {
	case "crl":
		return InputCRL
	case "ocsp":
		return InputOCSP
	default:
		return InputCert
	}
}
