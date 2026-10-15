package tests

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/operator"
)

// TestDomainPackagesDoNotDependOnNodeProjections keeps domain decisions on
// typed facts. Node trees are a policy representation built from those facts.
func TestDomainPackagesDoNotDependOnNodeProjections(t *testing.T) {
	const module = "github.com/cavoq/PCL/internal/"
	projections := []string{"certnode", "crlnode", "ocspnode", "x509node"}
	forbidden := map[string][]string{
		"path":     append([]string{"node"}, projections...),
		"operator": projections,
	}

	for pkg, imports := range forbidden {
		files, err := filepath.Glob(filepath.Join("..", "internal", pkg, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("list %s sources: %v", pkg, err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			source, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), file, source, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range parsed.Imports {
				imported, _ := strconv.Unquote(spec.Path.Value)
				for _, name := range imports {
					if imported == module+name {
						t.Errorf("%s imports %s", file, imported)
					}
				}
			}
		}
	}
}

// TestCertificatesParseThroughCertparse keeps one certificate parser, so
// certificates parse the same way from files, CA Issuers responses and OCSP
// responses.
func TestCertificatesParseThroughCertparse(t *testing.T) {
	const zcryptoX509 = "github.com/zmap/zcrypto/x509"
	allowed := map[string]bool{
		filepath.Join("..", "internal", "certparse"): true,
		filepath.Join("..", "internal", "testpki"):   true,
	}
	for _, root := range []string{filepath.Join("..", "internal"), filepath.Join("..", "cmd")} {
		err := filepath.WalkDir(root, func(file string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || allowed[filepath.Dir(file)] ||
				!strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
				return err
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
			if err != nil {
				return err
			}
			for _, spec := range parsed.Imports {
				if imported, _ := strconv.Unquote(spec.Path.Value); imported != zcryptoX509 {
					continue
				}
				name := "x509"
				if spec.Name != nil {
					name = spec.Name.Name
				}
				ast.Inspect(parsed, func(n ast.Node) bool {
					selector, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == name &&
						strings.HasPrefix(selector.Sel.Name, "ParseCertificate") {
						t.Errorf("%s calls %s.%s; use certparse.ParseCertificate", file, name, selector.Sel.Name)
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestRuleEvaluationNamesNoOperator keeps operator semantics, including how an
// evaluation is explained, inside the operators.
func TestRuleEvaluationNamesNoOperator(t *testing.T) {
	names := make(map[string]bool)
	for _, name := range operator.DefaultRegistry().Names() {
		names[name] = true
	}
	files, err := filepath.Glob(filepath.Join("..", "internal", "rule", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			literal, ok := n.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			if value, err := strconv.Unquote(literal.Value); err == nil && names[value] {
				t.Errorf("%s names operator %q", file, value)
			}
			return true
		})
	}
}
