package node

import "strings"

func (n *Node) Print() string {
	return n.PrintWith(FormatValue)
}

// PrintWith renders the tree with format applied to every node value.
func (n *Node) PrintWith(format func(any) string) string {
	var b strings.Builder
	if n != nil {
		writeNodeLine(&b, n, format)
		printChildren(&b, n, "", format)
	}
	return b.String()
}

func printChildren(b *strings.Builder, n *Node, prefix string, format func(any) string) {
	keys := SortedChildKeys(n)
	for i, key := range keys {
		child := n.Children[key]
		if child == nil {
			continue
		}
		connector, childPrefix := "├── ", prefix+"│   "
		if i == len(keys)-1 {
			connector, childPrefix = "└── ", prefix+"    "
		}
		b.WriteString(prefix + connector)
		writeNodeLine(b, child, format)
		printChildren(b, child, childPrefix, format)
	}
}

func writeNodeLine(b *strings.Builder, n *Node, format func(any) string) {
	b.WriteString(n.Name)
	if n.Value != nil {
		b.WriteString(": ")
		b.WriteString(format(n.Value))
	}
	b.WriteString("\n")
}
