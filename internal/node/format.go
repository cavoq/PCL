package node

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"time"
)

// ValueKind names the kind of a node value for policy authors: string, int,
// number, bool, bytes or time, the Go type for anything else, and "" for a
// node without a value.
func ValueKind(value any) string {
	switch value.(type) {
	case nil:
		return ""
	case string:
		return "string"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, *big.Int:
		return "int"
	case float32, float64:
		return "number"
	case bool:
		return "bool"
	case []byte:
		return "bytes"
	case time.Time:
		return "time"
	default:
		return fmt.Sprintf("%T", value)
	}
}

// FormatValue renders a node value for display: bytes as lowercase hex and
// times in RFC 3339 UTC. Other values use their default formatting.
func FormatValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case []byte:
		return hex.EncodeToString(typed)
	case time.Time:
		return typed.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", value)
	}
}

// SortedChildKeys orders child keys with collection indexes first in numeric
// order, then the remaining keys lexically.
func SortedChildKeys(n *Node) []string {
	if n == nil {
		return nil
	}
	keys := make([]string, 0, len(n.Children))
	for key := range n.Children {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, leftIndexed := collectionIndex(keys[i])
		right, rightIndexed := collectionIndex(keys[j])
		switch {
		case leftIndexed && rightIndexed && left != right:
			return left < right
		case leftIndexed != rightIndexed:
			return leftIndexed
		default:
			return keys[i] < keys[j]
		}
	})
	return keys
}

// PathEntry is one node reachable from a root, with the dotted path that
// Resolve accepts for it.
type PathEntry struct {
	Path string
	Node *Node
}

// Paths lists every node of the tree rooted at n, depth first, starting with
// n itself. Paths begin with the root's name, as rule targets do.
func Paths(n *Node) []PathEntry {
	if n == nil {
		return nil
	}
	var entries []PathEntry
	var visit func(path string, current *Node)
	visit = func(path string, current *Node) {
		entries = append(entries, PathEntry{Path: path, Node: current})
		for _, key := range SortedChildKeys(current) {
			if child := current.Children[key]; child != nil {
				visit(path+"."+key, child)
			}
		}
	}
	visit(n.Name, n)
	return entries
}
