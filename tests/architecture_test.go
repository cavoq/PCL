package tests

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
