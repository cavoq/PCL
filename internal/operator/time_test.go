package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestUTCTimeHasZulu(t *testing.T) {
	op := UTCTimeHasZulu{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "node without hasZulu child returns false",
			node: node.New("test", "2501011200Z"),
			want: false,
		},
		{
			name: "hasZulu true returns true",
			node: func() *node.Node {
				n := node.New("test", "2501011200Z")
				n.Children["hasZulu"] = node.New("hasZulu", true)
				return n
			}(),
			want: true,
		},
		{
			name: "hasZulu false returns false",
			node: func() *node.Node {
				n := node.New("test", "2501011200+0000")
				n.Children["hasZulu"] = node.New("hasZulu", false)
				return n
			}(),
			want: false,
		},
		{
			name: "hasZulu non-bool returns false",
			node: func() *node.Node {
				n := node.New("test", "2501011200Z")
				n.Children["hasZulu"] = node.New("hasZulu", "true")
				return n
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("UTCTimeHasZulu.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("UTCTimeHasZulu.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUTCTimeHasSeconds(t *testing.T) {
	op := UTCTimeHasSeconds{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "node without hasSeconds child returns false",
			node: node.New("test", "2501011200Z"),
			want: false,
		},
		{
			name: "hasSeconds true returns true",
			node: func() *node.Node {
				n := node.New("test", "250101120000Z")
				n.Children["hasSeconds"] = node.New("hasSeconds", true)
				return n
			}(),
			want: true,
		},
		{
			name: "hasSeconds false returns false",
			node: func() *node.Node {
				n := node.New("test", "2501011200Z")
				n.Children["hasSeconds"] = node.New("hasSeconds", false)
				return n
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("UTCTimeHasSeconds.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("UTCTimeHasSeconds.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGeneralizedTimeHasZulu(t *testing.T) {
	op := GeneralizedTimeHasZulu{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "hasZulu true returns true",
			node: func() *node.Node {
				n := node.New("test", "20250101120000Z")
				n.Children["hasZulu"] = node.New("hasZulu", true)
				return n
			}(),
			want: true,
		},
		{
			name: "hasZulu false returns false",
			node: func() *node.Node {
				n := node.New("test", "20250101120000+0000")
				n.Children["hasZulu"] = node.New("hasZulu", false)
				return n
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("GeneralizedTimeHasZulu.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("GeneralizedTimeHasZulu.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGeneralizedTimeNoFraction(t *testing.T) {
	op := GeneralizedTimeNoFraction{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "UTCTime (isUTC true) returns false",
			node: func() *node.Node {
				n := node.New("test", "2501011200Z")
				n.Children["isUTC"] = node.New("isUTC", true)
				return n
			}(),
			want: false,
		},
		{
			name: "GeneralizedTime without fraction returns true",
			node: func() *node.Node {
				n := node.New("test", "20250101120000Z")
				n.Children["isUTC"] = node.New("isUTC", false)
				n.Children["format"] = node.New("format", "20060102150405Z")
				return n
			}(),
			want: true,
		},
		{
			name: "GeneralizedTime with fraction returns false",
			node: func() *node.Node {
				n := node.New("test", "20250101120000.123Z")
				n.Children["isUTC"] = node.New("isUTC", false)
				n.Children["format"] = node.New("format", "20060102150405.999Z")
				return n
			}(),
			want: false,
		},
		{
			name: "GeneralizedTime without format child returns false",
			node: func() *node.Node {
				n := node.New("test", "20250101120000Z")
				n.Children["isUTC"] = node.New("isUTC", false)
				return n
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("GeneralizedTimeNoFraction.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("GeneralizedTimeNoFraction.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUTCTime(t *testing.T) {
	op := IsUTCTime{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "isUTC true returns true",
			node: func() *node.Node {
				n := node.New("test", "2501011200Z")
				n.Children["isUTC"] = node.New("isUTC", true)
				return n
			}(),
			want: true,
		},
		{
			name: "isUTC false returns false (GeneralizedTime)",
			node: func() *node.Node {
				n := node.New("test", "20250101120000Z")
				n.Children["isUTC"] = node.New("isUTC", false)
				return n
			}(),
			want: false,
		},
		{
			name: "no isUTC child returns false",
			node: node.New("test", "2501011200Z"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("IsUTCTime.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("IsUTCTime.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsGeneralizedTime(t *testing.T) {
	op := IsGeneralizedTime{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "isUTC false returns true (GeneralizedTime)",
			node: func() *node.Node {
				n := node.New("test", "20250101120000Z")
				n.Children["isUTC"] = node.New("isUTC", false)
				return n
			}(),
			want: true,
		},
		{
			name: "isUTC true returns false (UTCTime)",
			node: func() *node.Node {
				n := node.New("test", "2501011200Z")
				n.Children["isUTC"] = node.New("isUTC", true)
				return n
			}(),
			want: false,
		},
		{
			name: "no isUTC child returns false",
			node: node.New("test", "20250101120000Z"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("IsGeneralizedTime.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("IsGeneralizedTime.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}