package node

type Node struct {
	Name     string
	Value    any
	Children map[string]*Node
}

func New(name string, value any) *Node {
	return &Node{
		Name:     name,
		Value:    value,
		Children: map[string]*Node{},
	}
}
