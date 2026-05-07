package operator

import (
	"github.com/cavoq/PCL/internal/node"
)

// UTCTimeHasZulu validates that UTCTime has 'Z' suffix per RFC 5280 4.1.2.5.1.
// UTCTime format MUST end with 'Z' (not timezone offset).
type UTCTimeHasZulu struct{}

func (UTCTimeHasZulu) Name() string { return "utctimeHasZulu" }

func (UTCTimeHasZulu) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Check hasZulu child from encoding info
	hasZuluNode := n.Children["hasZulu"]
	if hasZuluNode == nil || hasZuluNode.Value == nil {
		return false, nil
	}

	if b, ok := hasZuluNode.Value.(bool); ok {
		return b, nil
	}

	return false, nil
}

// UTCTimeHasSeconds validates that UTCTime includes seconds per RFC 5280 4.1.2.5.1.
// Seconds MUST be present even if the value is 00.
type UTCTimeHasSeconds struct{}

func (UTCTimeHasSeconds) Name() string { return "utctimeHasSeconds" }

func (UTCTimeHasSeconds) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Check hasSeconds child from encoding info
	hasSecondsNode := n.Children["hasSeconds"]
	if hasSecondsNode == nil || hasSecondsNode.Value == nil {
		return false, nil
	}

	if b, ok := hasSecondsNode.Value.(bool); ok {
		return b, nil
	}

	return false, nil
}

// GeneralizedTimeHasZulu validates that GeneralizedTime has 'Z' suffix.
// GeneralizedTime MUST end with 'Z' per RFC 5280.
type GeneralizedTimeHasZulu struct{}

func (GeneralizedTimeHasZulu) Name() string { return "generalizedTimeHasZulu" }

func (GeneralizedTimeHasZulu) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Check hasZulu child from encoding info
	hasZuluNode := n.Children["hasZulu"]
	if hasZuluNode == nil || hasZuluNode.Value == nil {
		return false, nil
	}

	if b, ok := hasZuluNode.Value.(bool); ok {
		return b, nil
	}

	return false, nil
}

// GeneralizedTimeNoFraction validates that GeneralizedTime has no fractional seconds.
// Fractional seconds are not recommended by RFC 5280.
type GeneralizedTimeNoFraction struct{}

func (GeneralizedTimeNoFraction) Name() string { return "generalizedTimeNoFraction" }

func (GeneralizedTimeNoFraction) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Check isUTC (false for GeneralizedTime) to ensure we're checking GeneralizedTime
	isUTCNode := n.Children["isUTC"]
	if isUTCNode == nil || isUTCNode.Value == nil {
		return false, nil
	}

	isUTC, ok := isUTCNode.Value.(bool)
	if !ok {
		return false, nil
	}

	// This operator only applies to GeneralizedTime (isUTC=false)
	if isUTC {
		return false, nil // Skip for UTCTime
	}

	// For GeneralizedTime, check hasFraction from format string
	// We derive this from the format child
	formatNode := n.Children["format"]
	if formatNode == nil || formatNode.Value == nil {
		return false, nil
	}

	format, ok := formatNode.Value.(string)
	if !ok {
		return false, nil
	}

	// Fractional seconds are indicated by '.' in the format
	hasFraction := false
	for _, c := range format {
		if c == '.' {
			hasFraction = true
			break
		}
	}

	return !hasFraction, nil
}

// IsUTCTime checks if the time encoding is UTCTime (tag 23).
type IsUTCTime struct{}

func (IsUTCTime) Name() string { return "isUTCTime" }

func (IsUTCTime) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	isUTCNode := n.Children["isUTC"]
	if isUTCNode == nil || isUTCNode.Value == nil {
		return false, nil
	}

	if b, ok := isUTCNode.Value.(bool); ok {
		return b, nil
	}

	return false, nil
}

// IsGeneralizedTime checks if the time encoding is GeneralizedTime (tag 24).
type IsGeneralizedTime struct{}

func (IsGeneralizedTime) Name() string { return "isGeneralizedTime" }

func (IsGeneralizedTime) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	isUTCNode := n.Children["isUTC"]
	if isUTCNode == nil || isUTCNode.Value == nil {
		return false, nil
	}

	if b, ok := isUTCNode.Value.(bool); ok {
		return !b, nil // GeneralizedTime when isUTC is false
	}

	return false, nil
}