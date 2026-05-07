// Package cert provides certificate loading, parsing and chain building.
package cert

import "github.com/cavoq/PCL/internal/node"

type Builder interface {
	Build(any) *node.Node
}
