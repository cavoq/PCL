package node

import "strings"

func (n *Node) Resolve(path string) (*Node, bool) {
	if path == "" {
		return n, true
	}

	current := n
	parts := strings.Split(path, ".")

	for _, p := range parts {
		next, ok := current.Children[p]
		if !ok {
			return nil, false
		}
		current = next
	}

	return current, true
}
