package path

import (
	"crypto"
	"fmt"
	"slices"
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/testpki"
)

// crossCertifiedMesh builds levels of width same-name CAs below width
// self-signed roots. Every CA key is certified by every key one level up, so
// each certificate has width*width same-name issuer candidates of which width
// verify. It returns a leaf below the last level, the CA certificates and the
// roots.
func crossCertifiedMesh(tb testing.TB, width, levels int) (*cert.Info, []*cert.Info, []*cert.Info) {
	tb.Helper()
	serial := int64(0)
	next := func() testpki.Option {
		serial++
		return testpki.Serial(serial)
	}

	var roots, intermediates []*cert.Info
	parents := make([]*testpki.Certificate, width)
	for index := range parents {
		parents[index] = testpki.IssueWithKey(tb, "Level 0", testpki.ECDSAKey(tb), nil, testpki.CA(), next())
		roots = append(roots, &cert.Info{Cert: parents[index].Cert})
	}
	for level := 1; level <= levels; level++ {
		subject := fmt.Sprintf("Level %d", level)
		current := make([]*testpki.Certificate, width)
		for index := range current {
			var key crypto.Signer = testpki.ECDSAKey(tb)
			for _, parent := range parents {
				issued := testpki.IssueWithKey(tb, subject, key, parent, testpki.CA(), next())
				intermediates = append(intermediates, &cert.Info{Cert: issued.Cert})
				if current[index] == nil {
					current[index] = issued
				}
			}
		}
		parents = current
	}
	leaf := testpki.IssueWithKey(tb, "Leaf", testpki.ECDSAKey(tb), parents[0], next())
	return &cert.Info{Cert: leaf.Cert}, intermediates, roots
}

func BenchmarkConstructCrossCertifiedMesh(b *testing.B) {
	for _, size := range []struct{ width, levels int }{{2, 3}, {2, 5}, {3, 3}, {3, 4}, {4, 6}, {8, 8}} {
		b.Run(fmt.Sprintf("width%d_levels%d", size.width, size.levels), func(b *testing.B) {
			leaf, intermediates, roots := crossCertifiedMesh(b, size.width, size.levels)
			b.ResetTimer()
			for b.Loop() {
				construction, err := Construct([]*cert.Info{leaf}, intermediates, roots, 0)
				if err != nil || !construction.Anchored {
					b.Fatalf("construction = %#v, %v", construction, err)
				}
			}
		})
	}
}

func TestConstructBoundsUnanchoredSearch(t *testing.T) {
	leaf, intermediates, roots := crossCertifiedMesh(t, 2, 3)
	complete, err := Construct([]*cert.Info{leaf}, append(intermediates, roots...), nil, 0)
	if err != nil || complete.Anchored || complete.Truncated || len(complete.Chain) != 5 {
		t.Fatalf("complete search = %+v, %v; want an untruncated five-certificate path", complete, err)
	}

	budget := unanchoredSearchBudget
	unanchoredSearchBudget = 3
	t.Cleanup(func() { unanchoredSearchBudget = budget })
	first, err := Construct([]*cert.Info{leaf}, append(intermediates, roots...), nil, 0)
	if err != nil || !first.Truncated || first.Anchored || len(first.Chain) == 0 {
		t.Fatalf("budgeted search = %+v, %v; want a truncated unanchored path", first, err)
	}
	second, _ := Construct([]*cert.Info{leaf}, append(intermediates, roots...), nil, 0)
	if !slices.Equal(first.Chain, second.Chain) {
		t.Fatal("budgeted search is not deterministic")
	}

	anchored, err := Construct([]*cert.Info{leaf}, intermediates, roots, 0)
	if err != nil || !anchored.Anchored || anchored.Truncated {
		t.Fatalf("anchored search = %+v, %v; the budget must not limit anchored paths", anchored, err)
	}
}
