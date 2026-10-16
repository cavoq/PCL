package rule

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

// Effective-date bases: the time a rule's effective window is compared with.
const (
	// EffectiveByIssuance compares the input's issuance time: a certificate's
	// notBefore, a CRL's thisUpdate or an OCSP response's producedAt.
	// Certificates do not record their issuance, so notBefore stands in for it.
	EffectiveByIssuance = "issuance"
	// EffectiveByValidation compares the evaluation time.
	EffectiveByValidation = "validation"
)

// Effective limits a rule to inputs whose basis time lies in [From, Until),
// so a policy can state successive versions of a requirement. A zero bound
// is open.
type Effective struct {
	Basis string `yaml:"basis"`
	From  Date   `yaml:"from,omitempty"`
	Until Date   `yaml:"until,omitempty"`
}

// Date is a policy time given as RFC 3339 or YYYY-MM-DD (UTC midnight),
// quoted or not.
type Date struct{ time.Time }

// ParseDate parses an RFC 3339 time or a YYYY-MM-DD date at UTC midnight.
func ParseDate(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("time %q is not RFC 3339 or YYYY-MM-DD", value)
}

func (d *Date) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: a date must be a scalar", value.Line)
	}
	parsed, err := ParseDate(value.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", value.Line, err)
	}
	d.Time = parsed
	return nil
}

func (d Date) MarshalYAML() (any, error) {
	return d.Format(time.RFC3339), nil
}

// issuanceTimes names the issuance time of each input namespace.
var issuanceTimes = map[string]string{
	node.CertificateNamespace: "validity.notBefore",
	node.CRLNamespace:         "thisUpdate",
	node.OCSPNamespace:        "producedAt",
}

// notEffective explains why the rule is not in effect for the evaluated
// input, or returns "" when it is.
func notEffective(effective *Effective, root *node.Node, ctx *operator.EvaluationContext) string {
	if effective == nil {
		return ""
	}
	at, label, ok := effectiveBasisTime(effective.Basis, root, ctx)
	if !ok {
		return "the input has no issuance time to decide the effective date"
	}
	stamp := at.UTC().Format(time.RFC3339)
	switch {
	case !effective.From.IsZero() && at.Before(effective.From.Time):
		return fmt.Sprintf("not in effect: %s %s is before %s", label, stamp, effective.From.UTC().Format(time.RFC3339))
	case !effective.Until.IsZero() && !at.Before(effective.Until.Time):
		return fmt.Sprintf("not in effect: %s %s is not before %s", label, stamp, effective.Until.UTC().Format(time.RFC3339))
	default:
		return ""
	}
}

func effectiveBasisTime(basis string, root *node.Node, ctx *operator.EvaluationContext) (time.Time, string, bool) {
	if basis == EffectiveByValidation {
		if ctx == nil || ctx.Now.IsZero() {
			return time.Now(), "validation time", true
		}
		return ctx.Now, "validation time", true
	}
	if root == nil {
		return time.Time{}, "", false
	}
	field, ok := issuanceTimes[root.Name]
	if !ok {
		return time.Time{}, "", false
	}
	issued, found := root.Resolve(root.Name + "." + field)
	if !found {
		return time.Time{}, "", false
	}
	at, ok := issued.Value.(time.Time)
	return at, "issuance (" + field + ")", ok
}
