package node

import "strings"

// Wildcard is the path segment that Lookup expands to every collection
// element of the current node.
const Wildcard = "*"

// Resolution is the result of Lookup.
type Resolution struct {
	// Node is the resolved node. When the path contains Wildcard it is a
	// synthetic node named Wildcard whose collection elements are the matches.
	Node *Node
	// Partial reports that at least one wildcard branch did not resolve the
	// remainder of the path.
	Partial bool
}

// Resolve resolves a dot-separated path from n. A leading segment equal to
// n's own name is ignored, so rule targets may include the root namespace.
// Path segments are matched as described for Lookup, without wildcards.
func (n *Node) Resolve(path string) (*Node, bool) {
	if path == "" {
		return n, true
	}
	if n == nil {
		return nil, false
	}

	parts := strings.Split(path, ".")
	if parts[0] == n.Name {
		parts = parts[1:]
	}

	resolved := walk(n, parts, false)
	return resolved.Node, resolved.Node != nil
}

// Lookup resolves a dot-separated path relative to n. A segment that does not
// name a child is combined with the following segments, longest run first, so
// dotted keys such as OIDs ("extensions.2.5.29.15.critical") resolve. A
// Wildcard segment matches every collection element of the current node.
func (n *Node) Lookup(path string) Resolution {
	if n == nil || path == "" {
		return Resolution{Node: n}
	}
	return walk(n, strings.Split(path, "."), true)
}

func walk(current *Node, parts []string, wildcards bool) Resolution {
	for len(parts) > 0 {
		if current == nil {
			return Resolution{}
		}
		if wildcards && parts[0] == Wildcard {
			return expandWildcard(current, parts[1:])
		}

		next, consumed := current.childForSegments(parts)
		if next == nil {
			return Resolution{}
		}
		current = next
		parts = parts[consumed:]
	}
	return Resolution{Node: current}
}

// childForSegments returns the child named by the first segment, or else by
// the longest run of leading segments joined with dots, and the number of
// segments consumed.
func (n *Node) childForSegments(parts []string) (*Node, int) {
	if child, ok := n.Children[parts[0]]; ok {
		return child, 1
	}
	for end := len(parts); end > 1; end-- {
		if child, ok := n.Children[strings.Join(parts[:end], ".")]; ok {
			return child, end
		}
	}
	return nil, 0
}

func expandWildcard(current *Node, rest []string) Resolution {
	matches := New(Wildcard, nil)
	partial := false

	for _, element := range CollectionElements(current) {
		if len(rest) == 0 {
			matches.AddElement(element)
			continue
		}

		remaining := rest
		// An element named like the next segment stands for that segment.
		if element.Name == remaining[0] {
			remaining = remaining[1:]
		}
		resolved := walk(element, remaining, true)
		partial = partial || resolved.Partial

		switch {
		case resolved.Node == nil:
			partial = true
		case len(resolved.Node.Children) > 0:
			for _, match := range CollectionElements(resolved.Node) {
				matches.AddElement(match)
			}
		default:
			matches.AddElement(resolved.Node)
		}
	}

	if len(matches.Children) == 0 {
		return Resolution{Partial: partial}
	}
	return Resolution{Node: matches, Partial: partial}
}
