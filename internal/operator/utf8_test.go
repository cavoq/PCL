package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestByteOrderMarkOperators(t *testing.T) {
	const bom = "\xEF\xBB\xBF"
	has := func(name string, op Operator, value any, want bool) evaluationCase {
		return evaluationCase{name: name, op: op, node: node.New("test", value), want: want}
	}
	checkEvaluations(t, nil, []evaluationCase{
		has("utf8NoBom: string without BOM", UTF8NoBOM{}, "normal UTF-8 string", true),
		has("utf8NoBom: string with BOM", UTF8NoBOM{}, bom+"string with BOM", false),
		has("utf8NoBom: bytes without BOM", UTF8NoBOM{}, []byte("normal bytes"), true),
		has("utf8NoBom: bytes with BOM", UTF8NoBOM{}, []byte(bom+"bytes with BOM"), false),
		has("utf8NoBom: empty string", UTF8NoBOM{}, "", true),
		has("utf8NoBom: empty bytes", UTF8NoBOM{}, []byte{}, true),
		// Values other than strings and bytes cannot have a BOM.
		has("utf8NoBom: non-string value", UTF8NoBOM{}, 123, true),
		has("utf8NoBom: Chinese multi-byte string", UTF8NoBOM{}, "医者@example.com", true),
		has("utf8NoBom: Japanese multi-byte string", UTF8NoBOM{}, "テスト", true),
		has("utf8NoBom: multi-byte bytes with BOM", UTF8NoBOM{}, []byte(bom+"医者@example.com"), false),
		has("containsBom: string without BOM", ContainsBOM{}, "normal string", false),
		has("containsBom: string with BOM", ContainsBOM{}, bom+"string with BOM", true),
	})
}
