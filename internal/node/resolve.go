package node

import "strings"

func (n *Node) Resolve(path string) (*Node, bool) {
	if path == "" {
		return n, true
	}

	current := n
	parts := strings.Split(path, ".")

	// If the first part matches this node's name, skip it
	if len(parts) > 0 && parts[0] == n.Name {
		parts = parts[1:]
	}

	for _, p := range parts {
		next, ok := current.Children[p]
		if !ok {
			return nil, false
		}
		current = next
	}

	return current, true
}
