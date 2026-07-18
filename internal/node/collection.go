package node

import (
	"sort"
	"strconv"
)

// CollectionElements returns the logical elements represented by n's children.
//
// Collection nodes use non-negative integer keys for their elements and may
// also expose metadata or named aliases. When at least one indexed child is
// present, only indexed children are returned, ordered by numeric index. For
// compatibility with ordinary object nodes, nodes without indexed children
// return their named children in key order.
//
// A child referenced by more than one key is returned only once. Nil children
// are not elements.
func CollectionElements(n *Node) []*Node {
	if n == nil || len(n.Children) == 0 {
		return nil
	}

	type indexedChild struct {
		index int
		key   string
		node  *Node
	}

	indexed := make([]indexedChild, 0, len(n.Children))
	for key, child := range n.Children {
		index, ok := collectionIndex(key)
		if ok {
			indexed = append(indexed, indexedChild{index: index, key: key, node: child})
		}
	}
	if len(indexed) > 0 {
		sort.Slice(indexed, func(i, j int) bool {
			if indexed[i].index == indexed[j].index {
				return indexed[i].key < indexed[j].key
			}
			return indexed[i].index < indexed[j].index
		})
		elements := make([]*Node, 0, len(indexed))
		seen := make(map[*Node]struct{}, len(indexed))
		for _, child := range indexed {
			elements = appendUniqueElement(elements, seen, child.node)
		}
		return elements
	}

	keys := make([]string, 0, len(n.Children))
	for key := range n.Children {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	elements := make([]*Node, 0, len(keys))
	seen := make(map[*Node]struct{}, len(keys))
	for _, key := range keys {
		elements = appendUniqueElement(elements, seen, n.Children[key])
	}
	return elements
}

// AddElement appends an element under the first unused non-negative integer
// key. It is intended for collection nodes that may also contain metadata.
func (n *Node) AddElement(element *Node) {
	if n == nil {
		return
	}
	if n.Children == nil {
		n.Children = make(map[string]*Node)
	}
	for index := 0; ; index++ {
		key := strconv.Itoa(index)
		if _, exists := n.Children[key]; !exists {
			n.Children[key] = element
			return
		}
	}
}

func collectionIndex(key string) (int, bool) {
	if key == "" {
		return 0, false
	}
	for _, character := range key {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	index, err := strconv.Atoi(key)
	return index, err == nil
}

func appendUniqueElement(elements []*Node, seen map[*Node]struct{}, element *Node) []*Node {
	if element == nil {
		return elements
	}
	if _, exists := seen[element]; exists {
		return elements
	}
	seen[element] = struct{}{}
	return append(elements, element)
}
