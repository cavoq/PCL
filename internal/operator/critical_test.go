package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestCriticality(t *testing.T) {
	critical := tree("keyUsage", nil, node.New("critical", true))
	nonCritical := tree("subjectKeyIdentifier", nil, node.New("critical", false))
	noField := node.New("extension", nil)
	checkEvaluations(t, nil, []evaluationCase{
		{name: "isCritical: critical extension", op: IsCritical{}, node: critical, want: true},
		{name: "isCritical: non-critical extension", op: IsCritical{}, node: nonCritical},
		{name: "isCritical: no critical field", op: IsCritical{}, node: noField},
		{name: "isCritical: nil node", op: IsCritical{}},
		{name: "notCritical: critical extension", op: NotCritical{}, node: critical},
		{name: "notCritical: non-critical extension", op: NotCritical{}, node: nonCritical, want: true},
		{name: "notCritical: no critical field", op: NotCritical{}, node: noField, want: true},
		{name: "notCritical: nil node", op: NotCritical{}},
	})
}
