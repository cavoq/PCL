package operator

import (
	"maps"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/node"
)

func TestDateOperators(t *testing.T) {
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-24*time.Hour), now.Add(24*time.Hour)
	ctx := &EvaluationContext{Now: now}

	tests := []struct {
		name     string
		op       Operator
		value    time.Time
		operands []any
		want     bool
	}{
		{"past is before now", Before{}, past, nil, true},
		{"future is not before now", Before{}, future, nil, false},
		{"past is before explicit now", Before{}, past, []any{"now"}, true},
		{"future is after now", After{}, future, nil, true},
		{"past is not after now", After{}, past, nil, false},
		{"strict before excludes equality", Before{}, now, nil, false},
		{"strict after excludes equality", After{}, now, nil, false},
		{"on or before includes equality", OnOrBefore{}, now, nil, true},
		{"on or after includes equality", OnOrAfter{}, now, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.op.Evaluate(node.New("test", tt.value), ctx, tt.operands)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("%s = %v, want %v", tt.op.Name(), got, tt.want)
			}
		})
	}
}

func TestDateOperatorNilNode(t *testing.T) {
	ops := []Operator{Before{}, After{}}
	for _, op := range ops {
		got, _ := op.Evaluate(nil, nil, []any{})
		if got != false {
			t.Errorf("%s: nil node should return false", op.Name())
		}
	}
}

func TestDateDiff(t *testing.T) {
	now := time.Now()
	days := func(count int) time.Time { return now.Add(time.Duration(count) * 24 * time.Hour) }
	hours := func(count int) time.Time { return now.Add(time.Duration(count) * time.Hour) }
	// updates is a node whose thisUpdate is now.
	updates := func(nextUpdate time.Time) *node.Node {
		n := node.New("test", nil)
		n.Children["thisUpdate"] = node.New("thisUpdate", now)
		n.Children["nextUpdate"] = node.New("nextUpdate", nextUpdate)
		return n
	}
	// between bounds the interval from thisUpdate to nextUpdate.
	between := func(bounds map[string]any) []any {
		operand := map[string]any{"start": "thisUpdate", "end": "nextUpdate"}
		maps.Copy(operand, bounds)
		return []any{operand}
	}
	missingStart := node.New("test", nil)
	missingStart.Children["nextUpdate"] = node.New("nextUpdate", days(5))
	ocspInterval := map[string]any{"minHours": 8, "maxDays": 10}

	evaluate := func(name string, n *node.Node, operands []any, want, wantErr bool) evaluationCase {
		return evaluationCase{name: name, op: DateDiff{}, node: n, operands: operands, want: want, wantErr: wantErr}
	}
	checkEvaluations(t, nil, []evaluationCase{
		evaluate("nil node returns false", nil, between(map[string]any{"maxDays": 10}), false, false),
		evaluate("maxDays within limit", updates(days(5)), between(map[string]any{"maxDays": 10}), true, false),
		evaluate("maxDays exceeds limit", updates(days(15)), between(map[string]any{"maxDays": 10}), false, false),
		evaluate("maxMonths within limit", updates(now.AddDate(0, 6, 0)), between(map[string]any{"maxMonths": 12}), true, false),
		evaluate("maxMonths exceeds limit", updates(now.AddDate(0, 13, 0)), between(map[string]any{"maxMonths": 12}), false, false),
		evaluate("minDays within limit", updates(days(5)), between(map[string]any{"minDays": 3}), true, false),
		evaluate("minDays below limit", updates(days(2)), between(map[string]any{"minDays": 3}), false, false),
		evaluate("no operands returns error", node.New("test", nil), []any{}, false, true),
		evaluate("missing start returns error", node.New("test", nil), []any{map[string]any{"end": "nextUpdate", "maxDays": 10}}, false, true),
		evaluate("missing start node returns false", missingStart, between(map[string]any{"maxDays": 10}), false, false),
		evaluate("from alias for start", updates(days(5)), []any{map[string]any{"from": "thisUpdate", "end": "nextUpdate", "maxDays": 10}}, true, false),
		evaluate("int64 for maxDays", updates(days(5)), between(map[string]any{"maxDays": int64(10)}), true, false),
		evaluate("minHours within limit", updates(hours(12)), between(map[string]any{"minHours": 8}), true, false),
		evaluate("minHours below limit", updates(hours(4)), between(map[string]any{"minHours": 8}), false, false),
		evaluate("maxHours within limit", updates(hours(6)), between(map[string]any{"maxHours": 8}), true, false),
		evaluate("maxHours exceeds limit", updates(hours(12)), between(map[string]any{"maxHours": 8}), false, false),
		evaluate("OCSP validity interval 8 hours to 10 days - valid", updates(days(5)), between(ocspInterval), true, false),
		evaluate("OCSP validity interval 8 hours to 10 days - too short", updates(hours(4)), between(ocspInterval), false, false),
		evaluate("OCSP validity interval 8 hours to 10 days - too long", updates(days(12)), between(ocspInterval), false, false),
		evaluate("int64 for minHours", updates(hours(12)), between(map[string]any{"minHours": int64(8)}), true, false),
		evaluate("float64 for maxHours", updates(hours(6)), between(map[string]any{"maxHours": float64(8)}), true, false),
		evaluate("reversed interval fails maximum-only rule", updates(hours(-1)), between(map[string]any{"maxDays": 10}), false, false),
	})
}

func TestDateDiffValidatesStructuredOperands(t *testing.T) {
	checkOperandValidation(t, "dateDiff", []operandValidationCase{
		{
			name:     "start and maximum",
			operands: []any{map[string]any{"start": "thisUpdate", "maxDays": 10}},
		},
		{
			name:     "legacy from alias",
			operands: []any{map[string]any{"from": "thisUpdate", "minHours": 8}},
		},
		{
			name:     "unknown field",
			operands: []any{map[string]any{"start": "thisUpdate", "maxDay": 10}},
			wantErr:  true,
		},
		{
			name:     "conflicting start aliases",
			operands: []any{map[string]any{"start": "a", "from": "a", "maxDays": 10}},
			wantErr:  true,
		},
		{
			name:     "no duration bound",
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate"}},
			wantErr:  true,
		},
		{
			name:     "fractional bound",
			operands: []any{map[string]any{"start": "thisUpdate", "maxDays": 1.5}},
			wantErr:  true,
		},
		{
			name:     "inverted range",
			operands: []any{map[string]any{"start": "thisUpdate", "minDays": 11, "maxDays": 10}},
			wantErr:  true,
		},
		{
			name:     "inverted day to hour range",
			operands: []any{map[string]any{"start": "thisUpdate", "minDays": 2, "maxHours": 24}},
			wantErr:  true,
		},
		{
			name:     "inverted hour to day range",
			operands: []any{map[string]any{"start": "thisUpdate", "minHours": 49, "maxDays": 2}},
			wantErr:  true,
		},
		{
			name:     "mixed unit boundary",
			operands: []any{map[string]any{"start": "thisUpdate", "minDays": 1, "maxHours": 24}},
		},
		{
			name:     "duration overflow",
			operands: []any{map[string]any{"start": "thisUpdate", "maxDays": maxDateDiffDays + 1}},
			wantErr:  true,
		},
		{
			name:     "path whitespace",
			operands: []any{map[string]any{"start": " thisUpdate", "maxDays": 10}},
			wantErr:  true,
		},
		{
			name:       "legacy path diagnostic",
			operands:   []any{map[string]any{"from": " thisUpdate", "maxDays": 10}},
			wantErr:    true,
			wantDetail: "operands[0].from",
		},
	})
}
