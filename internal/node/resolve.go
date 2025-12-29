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

	for i := 0; i < len(parts); i++ {
		p := parts[i]
		next, ok := current.Children[p]
		if ok {
			current = next
			continue
		}

		matched := false
		for j := len(parts); j > i+1; j-- {
			candidate := strings.Join(parts[i:j], ".")
			next, ok = current.Children[candidate]
			if ok {
				current = next
				i = j - 1
				matched = true
				break
			}
		}
		if !matched {
			return nil, false
		}
	}

	return current, true
}
