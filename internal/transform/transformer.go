package transform

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/cavoq/PCL/internal/node"
	"github.com/zmap/zcrypto/x509"
)

type Handler func(name string, v any) *node.Node

type Transformer struct {
	handlers map[reflect.Type]Handler
	skip     map[string]struct{}
	nameFn   func(string) string
}

func NewTransformer() *Transformer {
	t := &Transformer{
		handlers: make(map[reflect.Type]Handler),
		skip: map[string]struct{}{
			"Raw":                     {},
			"RawTBSCertificate":       {},
			"RawSubjectPublicKeyInfo": {},
			"RawSubject":              {},
			"RawIssuer":               {},
			"Signature":               {},
		},
		nameFn: lowerFirst,
	}

	t.registerDefaults()
	return t
}

func (t *Transformer) Handle(typ reflect.Type, h Handler) {
	t.handlers[typ] = h
}

func (t *Transformer) Transform(name string, v any) *node.Node {
	return t.transform(name, reflect.ValueOf(v))
}

func (t *Transformer) transform(name string, v reflect.Value) *node.Node {
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return node.New(name, nil)
		}
		v = v.Elem()
	}

	if h, ok := t.handlers[v.Type()]; ok && v.CanInterface() {
		return h(name, v.Interface())
	}

	switch v.Kind() {
	case reflect.Struct:
		return t.transformStruct(name, v)
	case reflect.Slice, reflect.Array:
		return t.transformSlice(name, v)
	case reflect.Map:
		return t.transformMap(name, v)
	default:
		return node.New(name, t.valueOf(v))
	}
}

func (t *Transformer) transformStruct(name string, v reflect.Value) *node.Node {
	n := node.New(name, nil)
	typ := v.Type()

	for i := 0; i < v.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		if _, skip := t.skip[f.Name]; skip {
			continue
		}

		fieldName := t.nameFn(f.Name)
		child := t.transform(fieldName, v.Field(i))
		if child != nil {
			n.Children[fieldName] = child
		}
	}
	return n
}

func (t *Transformer) transformSlice(name string, v reflect.Value) *node.Node {
	if v.Len() == 0 {
		return node.New(name, []any{})
	}

	if isSimple(v.Type().Elem().Kind()) {
		vals := make([]any, v.Len())
		for i := 0; i < v.Len(); i++ {
			vals[i] = t.valueOf(v.Index(i))
		}
		return node.New(name, vals)
	}

	n := node.New(name, nil)
	for i := 0; i < v.Len(); i++ {
		key := fmt.Sprintf("%d", i)
		child := t.transform(key, v.Index(i))
		if child != nil {
			n.Children[key] = child
		}
	}
	return n
}

func (t *Transformer) transformMap(name string, v reflect.Value) *node.Node {
	n := node.New(name, nil)
	iter := v.MapRange()

	for iter.Next() {
		key := fmt.Sprintf("%v", iter.Key().Interface())
		child := t.transform(key, iter.Value())
		if child != nil {
			n.Children[key] = child
		}
	}
	return n
}

func (t *Transformer) valueOf(v reflect.Value) any {
	if !v.IsValid() || !v.CanInterface() {
		return nil
	}

	if h, ok := t.handlers[v.Type()]; ok {
		return h("", v.Interface()).Value
	}

	if s, ok := v.Interface().(fmt.Stringer); ok {
		return s.String()
	}

	return v.Interface()
}

func (t *Transformer) registerDefaults() {
	t.Handle(reflect.TypeOf(time.Time{}), func(name string, v any) *node.Node {
		return node.New(name, v.(time.Time))
	})

	t.Handle(reflect.TypeOf(&big.Int{}), func(name string, v any) *node.Node {
		if bi := v.(*big.Int); bi != nil {
			return node.New(name, bi.String())
		}
		return node.New(name, nil)
	})

	t.Handle(reflect.TypeOf(net.IP{}), func(name string, v any) *node.Node {
		return node.New(name, v.(net.IP).String())
	})

	t.Handle(reflect.TypeOf([]byte{}), func(name string, v any) *node.Node {
		b := v.([]byte)
		return node.New(name, hex.EncodeToString(b))
	})

	t.Handle(reflect.TypeOf(x509.KeyUsage(0)), handleKeyUsage)
}

func handleKeyUsage(name string, v any) *node.Node {
	ku := v.(x509.KeyUsage)
	n := node.New(name, int(ku))

	flags := []struct {
		name string
		flag x509.KeyUsage
	}{
		{"digitalSignature", x509.KeyUsageDigitalSignature},
		{"contentCommitment", x509.KeyUsageContentCommitment},
		{"keyEncipherment", x509.KeyUsageKeyEncipherment},
		{"dataEncipherment", x509.KeyUsageDataEncipherment},
		{"keyAgreement", x509.KeyUsageKeyAgreement},
		{"keyCertSign", x509.KeyUsageCertSign},
		{"crlSign", x509.KeyUsageCRLSign},
		{"encipherOnly", x509.KeyUsageEncipherOnly},
		{"decipherOnly", x509.KeyUsageDecipherOnly},
	}

	for _, f := range flags {
		n.Children[f.name] = node.New(f.name, ku&f.flag != 0)
	}
	return n
}

func isSimple(k reflect.Kind) bool {
	switch k {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64,
		reflect.String:
		return true
	}
	return false
}

func lowerFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
