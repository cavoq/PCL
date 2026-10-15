package x509node

import (
	"net"
	"strconv"
	"strings"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/cavoq/PCL/internal/x509ext"
)

// BuildGeneralName projects one decoded GeneralName. Certificate and CRL
// trees share this projection so the same name has the same node shape in
// every input.
func BuildGeneralName(name string, value x509ext.GeneralName) *node.Node {
	var (
		scalar        any = append([]byte(nil), value.RawValue...)
		typeID        string
		directoryName *node.Node
		edi           = value.EDIPartyName
	)
	switch value.Tag {
	case 0:
		if value.OtherName != nil {
			typeID = value.OtherName.TypeID
			scalar = value.OtherName.Value
		}
	case 1, 2, 6:
		scalar = string(value.RawValue)
	case 4:
		directoryName = BuildRawName("directoryName", value.RawValue)
		scalar = directoryName.Value
	case 7:
		scalar = net.IP(value.RawValue).String()
	case 8:
		identifier, err := x509ext.DecodeRegisteredID(value.RawDER)
		if err == nil {
			scalar = identifier
		}
	}

	n := node.New(name, CloneScalar(scalar))
	n.Children["value"] = node.New("value", CloneScalar(scalar))
	n.Children["type"] = node.New("type", x509ext.GeneralNameType(value.Tag))
	n.Children["tag"] = node.New("tag", value.Tag)
	n.Children["raw"] = node.New("raw", append([]byte(nil), value.RawDER...))
	n.Children["rawValue"] = node.New("rawValue", append([]byte(nil), value.RawValue...))

	switch value.Tag {
	case 0:
		if typeID != "" {
			n.Children["typeID"] = node.New("typeID", typeID)
		}
	case 4:
		n.Children["directoryName"] = directoryName
	case 5:
		if edi != nil {
			if edi.NameAssigner != nil {
				n.Children["nameAssigner"] = buildDirectoryStringNode("nameAssigner", *edi.NameAssigner)
			}
			n.Children["partyName"] = buildDirectoryStringNode("partyName", edi.PartyName)
		}
	case 6:
		if uri, ok := scalar.(string); ok {
			if separator := strings.IndexByte(uri, ':'); separator >= 0 {
				n.Children["scheme"] = node.New("scheme", uri[:separator])
			}
		}
	}

	return n
}

// AddGeneralNames adds names to parent under their zero-based indexes.
func AddGeneralNames(parent *node.Node, names []x509ext.GeneralName) {
	for index, name := range names {
		key := strconv.Itoa(index)
		parent.Children[key] = BuildGeneralName(key, name)
	}
}

// CloneScalar copies byte-slice node values so projected nodes never alias
// decoder buffers. Other values are returned unchanged.
func CloneScalar(value any) any {
	if bytes, ok := value.([]byte); ok {
		return append([]byte(nil), bytes...)
	}
	return value
}

func buildDirectoryStringNode(name string, value x509ext.DirectoryString) *node.Node {
	n := node.New(name, value.Value)
	n.Children["tag"] = node.New("tag", value.Tag)
	n.Children["encoding"] = node.New("encoding", x509asn1.StringTypeName(value.Tag))
	n.Children["raw"] = node.New("raw", append([]byte(nil), value.RawDER...))
	n.Children["rawValue"] = node.New("rawValue", append([]byte(nil), value.RawValue...))
	return n
}
