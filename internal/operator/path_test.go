package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/finding"
	pathpkg "github.com/cavoq/PCL/internal/path"
)

func TestPathValidReportsPathFindings(t *testing.T) {
	findings := []finding.Finding{{Code: "path.signature", Status: finding.StatusFail}}
	tests := []struct {
		name string
		ctx  *EvaluationContext
		want bool
	}{
		{name: "no context"},
		{name: "no path validation", ctx: &EvaluationContext{}},
		{name: "invalid path", ctx: &EvaluationContext{PathValidation: &pathpkg.Result{Findings: findings}}},
		{name: "valid path", ctx: &EvaluationContext{PathValidation: &pathpkg.Result{Valid: true, Findings: findings}}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := PathValid{}.Evaluate(nil, test.ctx, nil)
			if err != nil || got != test.want {
				t.Fatalf("Evaluate() = %v, %v; want %v", got, err, test.want)
			}
			reported := PathValid{}.Findings(nil, test.ctx, nil)
			if test.ctx == nil || test.ctx.PathValidation == nil {
				if reported != nil {
					t.Fatalf("Findings() = %#v without a path result", reported)
				}
				return
			}
			if len(reported) != 1 || &reported[0] == &test.ctx.PathValidation.Findings[0] {
				t.Fatalf("Findings() = %#v, want a copy of the path findings", reported)
			}
		})
	}
}
