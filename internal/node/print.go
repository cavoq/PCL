package node

import (
	"fmt"
	"sort"
	"strings"
)

func (n *Node) Print() string {
	var b strings.Builder
	printNode(&b, n, "", true)
	return b.String()
}

func printNode(b *strings.Builder, n *Node, prefix string, last bool) {
	if n == nil {
		return
	}

	if prefix != "" {
		if last {
			b.WriteString(prefix + "└── ")
		} else {
			b.WriteString(prefix + "├── ")
		}
	}

	b.WriteString(n.Name)
	if n.Value != nil {
		b.WriteString(": ")
		b.WriteString(fmt.Sprintf("%v", n.Value))
	}
	b.WriteString("\n")

	keys := make([]string, 0, len(n.Children))
	for k := range n.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		child := n.Children[k]
		nextPrefix := prefix
		if prefix != "" {
			if last {
				nextPrefix += "    "
			} else {
				nextPrefix += "│   "
			}
		}
		printNode(b, child, nextPrefix, i == len(keys)-1)
	}
}
