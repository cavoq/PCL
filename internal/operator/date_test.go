package operator

import (
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/node"
)

func TestBeforeOperator(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	ctx := &EvaluationContext{Now: now}

	tests := []struct {
		name     string
		value    time.Time
		expected bool
	}{
		{"past is before now", past, true},
		{"future is not before now", future, false},
	}

	op := Before{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, ctx, []any{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAfterOperator(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	ctx := &EvaluationContext{Now: now}

	tests := []struct {
		name     string
		value    time.Time
		expected bool
	}{
		{"future is after now", future, true},
		{"past is not after now", past, false},
	}

	op := After{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, ctx, []any{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBeforeWithExplicitNow(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)

	ctx := &EvaluationContext{Now: now}

	op := Before{}
	n := node.New("test", past)
	got, err := op.Evaluate(n, ctx, []any{"now"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("past should be before now")
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
	op := DateDiff{}
	now := time.Now()

	tests := []struct {
		name     string
		node     *node.Node
		operands []any
		want     bool
		wantErr  bool
	}{
		{
			name:     "nil node returns false",
			node:     nil,
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxDays": 10}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "maxDays within limit",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(5*24*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxDays": 10}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "maxDays exceeds limit",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(15*24*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxDays": 10}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "maxMonths within limit",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.AddDate(0, 6, 0))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxMonths": 12}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "maxMonths exceeds limit",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.AddDate(0, 13, 0))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxMonths": 12}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "minDays within limit",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(5*24*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "minDays": 3}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "minDays below limit",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(2*24*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "minDays": 3}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "no operands returns false",
			node: node.New("test", nil),
			operands: []any{},
			want:     false,
			wantErr:  false,
		},
		{
			name: "missing start returns false",
			node: node.New("test", nil),
			operands: []any{map[string]any{"end": "nextUpdate", "maxDays": 10}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "missing start node returns false",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["nextUpdate"] = node.New("nextUpdate", now.Add(5*24*time.Hour))
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxDays": 10}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "from alias for start",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(5*24*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"from": "thisUpdate", "end": "nextUpdate", "maxDays": 10}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "int64 and float64 for maxDays",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(5*24*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxDays": int64(10)}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "minHours within limit",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(12*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "minHours": 8}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "minHours below limit",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(4*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "minHours": 8}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "maxHours within limit",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(6*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxHours": 8}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "maxHours exceeds limit",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(12*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxHours": 8}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "OCSP validity interval 8 hours to 10 days - valid",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(5*24*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "minHours": 8, "maxDays": 10}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "OCSP validity interval 8 hours to 10 days - too short",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(4*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "minHours": 8, "maxDays": 10}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "OCSP validity interval 8 hours to 10 days - too long",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(12*24*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "minHours": 8, "maxDays": 10}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "int64 for minHours",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(12*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "minHours": int64(8)}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "float64 for maxHours",
			node: func() *node.Node {
				n := node.New("test", nil)
				thisUpdate := node.New("thisUpdate", now)
				nextUpdate := node.New("nextUpdate", now.Add(6*time.Hour))
				n.Children["thisUpdate"] = thisUpdate
				n.Children["nextUpdate"] = nextUpdate
				return n
			}(),
			operands: []any{map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxHours": float64(8)}},
			want:     true,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, tt.operands)
			if tt.wantErr && err == nil {
				t.Errorf("DateDiff.Evaluate() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("DateDiff.Evaluate() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("DateDiff.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}
