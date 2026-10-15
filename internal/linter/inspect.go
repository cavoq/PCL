package linter

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/evaluator"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
)

// InspectOptions selects how Inspect renders node trees.
type InspectOptions struct {
	// Paths lists every rule target path with its value kind and value
	// instead of printing the tree.
	Paths bool
}

// Inspect acquires the configured inputs exactly as Run does and writes the
// node tree that policies evaluate for each of them.
func Inspect(cfg Config, opts InspectOptions, w io.Writer) error {
	applyDefaults(&cfg)
	if err := cfg.validateInputs(); err != nil {
		return err
	}
	var cleanups cleanupStack
	defer cleanups.Close()

	diagnostics := diagnosticsWriter(cfg, w)
	inputs, err := acquireInputs(cfg, diagnostics, &cleanups)
	if err != nil {
		return err
	}
	subjects := buildSubjects(cfg, inputs, nil, operator.DefaultRegistry())
	if len(subjects) == 0 {
		return fmt.Errorf("no inputs to inspect")
	}

	switch cfg.OutputFmt {
	case output.FormatJSON:
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(inspectDocument(subjects, opts))
	case output.FormatYAML:
		encoder := yaml.NewEncoder(w)
		encoder.SetIndent(2)
		if err := encoder.Encode(inspectDocument(subjects, opts)); err != nil {
			return err
		}
		return encoder.Close()
	default:
		return writeInspectText(w, subjects, opts)
	}
}

// maxDisplayBytes bounds byte values in text output; JSON and YAML keep the
// complete hex value.
const maxDisplayBytes = 32

func displayValue(value any) string {
	if bytes, ok := value.([]byte); ok && len(bytes) > maxDisplayBytes {
		return fmt.Sprintf("%s… (%d bytes)", hex.EncodeToString(bytes[:maxDisplayBytes]), len(bytes))
	}
	return node.FormatValue(value)
}

func writeInspectText(w io.Writer, subjects []evaluator.Subject, opts InspectOptions) error {
	for index, subject := range subjects {
		if index > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "# %s\n", subjectHeading(subject)); err != nil {
			return err
		}
		if !opts.Paths {
			if _, err := io.WriteString(w, subject.Tree.PrintWith(displayValue)); err != nil {
				return err
			}
			continue
		}

		for _, entry := range node.Paths(subject.Tree) {
			if _, err := fmt.Fprintln(w, pathLine(entry)); err != nil {
				return err
			}
		}
	}
	return nil
}

// pathLine renders "path = value (kind)", or only the path for a node
// without a value.
func pathLine(entry node.PathEntry) string {
	if entry.Node.Value == nil {
		return entry.Path
	}
	return fmt.Sprintf("%s = %s (%s)", entry.Path, displayValue(entry.Node.Value), node.ValueKind(entry.Node.Value))
}

func subjectHeading(subject evaluator.Subject) string {
	heading := subject.Tree.Name
	input := subject.Context.Input
	if input.Kind != "" && input.Kind != subject.Tree.Name {
		heading += " (" + input.Kind + ")"
	}
	if input.Path != "" {
		heading += " " + input.Path
	}
	if source := input.Source.String(); source != "" {
		heading += " [" + source + "]"
	}
	return heading
}

type inspectedInput struct {
	Input  string          `json:"input" yaml:"input"`
	Type   string          `json:"type,omitempty" yaml:"type,omitempty"`
	File   string          `json:"file,omitempty" yaml:"file,omitempty"`
	Source string          `json:"source,omitempty" yaml:"source,omitempty"`
	Tree   *inspectedNode  `json:"tree,omitempty" yaml:"tree,omitempty"`
	Paths  []inspectedPath `json:"paths,omitempty" yaml:"paths,omitempty"`
}

type inspectedNode struct {
	Name     string           `json:"name" yaml:"name"`
	Kind     string           `json:"kind,omitempty" yaml:"kind,omitempty"`
	Value    any              `json:"value,omitempty" yaml:"value,omitempty"`
	Children []*inspectedNode `json:"children,omitempty" yaml:"children,omitempty"`
}

type inspectedPath struct {
	Path  string `json:"path" yaml:"path"`
	Kind  string `json:"kind,omitempty" yaml:"kind,omitempty"`
	Value any    `json:"value,omitempty" yaml:"value,omitempty"`
}

func inspectDocument(subjects []evaluator.Subject, opts InspectOptions) []inspectedInput {
	document := make([]inspectedInput, 0, len(subjects))
	for _, subject := range subjects {
		input := inspectedInput{Input: subject.Tree.Name}
		input.Type = subject.Context.Input.Kind
		input.File = subject.Context.Input.Path
		input.Source = subject.Context.Input.Source.String()
		if opts.Paths {
			for _, entry := range node.Paths(subject.Tree) {
				input.Paths = append(input.Paths, inspectedPath{
					Path:  entry.Path,
					Kind:  node.ValueKind(entry.Node.Value),
					Value: documentValue(entry.Node.Value),
				})
			}
		} else {
			input.Tree = inspectedTree(subject.Tree)
		}
		document = append(document, input)
	}
	return document
}

func inspectedTree(n *node.Node) *inspectedNode {
	inspected := &inspectedNode{
		Name:  n.Name,
		Kind:  node.ValueKind(n.Value),
		Value: documentValue(n.Value),
	}
	for _, key := range node.SortedChildKeys(n) {
		if child := n.Children[key]; child != nil {
			inspected.Children = append(inspected.Children, inspectedTree(child))
		}
	}
	return inspected
}

// documentValue keeps strings, numbers and booleans native and renders
// everything else as text, bytes as hex.
func documentValue(value any) any {
	switch value.(type) {
	case nil, string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return value
	default:
		return node.FormatValue(value)
	}
}
