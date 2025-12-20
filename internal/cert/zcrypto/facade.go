package zcrypto

import "github.com/cavoq/PCL/internal/node"

type Parser struct {
	loader  *Loader
	builder *ZCryptoBuilder
}

func NewParser() *Parser {
	return &Parser{
		loader:  NewLoader(),
		builder: NewZCryptoBuilder(),
	}
}

func (p *Parser) Parse(data []byte) (*node.Node, error) {
	cert, err := p.loader.Load(data)
	if err != nil {
		return nil, err
	}
	return p.builder.Build(cert), nil
}
