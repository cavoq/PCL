package cert

import "github.com/cavoq/PCL/internal/node"

type Builder interface {
	Build(any) *node.Node
}
