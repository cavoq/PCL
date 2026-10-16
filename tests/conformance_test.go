package tests

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// pathPolicy is the path engine's aggregate decision, shared by the PKITS and
// x509-limbo harnesses.
const pathPolicy = "policies/path-valid.yaml"

// knownGap documents conformance runs whose PCL outcome differs from the
// suite's expectation, grouped by cause.
type knownGap struct {
	Reason string   `yaml:"reason"`
	Cases  []string `yaml:"cases"`
}

// conformance compares PCL outcomes with a conformance suite's expectations.
// Known gaps may only shrink: a listed run that conforms, an unlisted run that
// does not, and a listed name that is no run all fail the test.
type conformance struct {
	suite      string
	gaps       map[string]string
	seen       map[string]bool
	conforming int
	gapped     int
}

func loadConformance(t *testing.T, suite, gapsPath string) *conformance {
	t.Helper()
	data, err := os.ReadFile(gapsPath)
	if err != nil {
		t.Fatalf("read %s known gaps: %v", suite, err)
	}
	var listed []knownGap
	if err := yaml.Unmarshal(data, &listed); err != nil {
		t.Fatalf("parse %s known gaps: %v", suite, err)
	}
	gaps := map[string]string{}
	for _, gap := range listed {
		if gap.Reason == "" {
			t.Fatalf("%s known gap group %v has no reason", suite, gap.Cases)
		}
		for _, name := range gap.Cases {
			if _, duplicate := gaps[name]; duplicate {
				t.Fatalf("%s known gap %s is listed twice", suite, name)
			}
			gaps[name] = gap.Reason
		}
	}
	return &conformance{suite: suite, gaps: gaps, seen: map[string]bool{}}
}

// check records one run with the outcome PCL reached and the one the suite
// expects.
func (c *conformance) check(t *testing.T, name, got, want string, failures []string) {
	t.Helper()
	c.seen[name] = true
	_, known := c.gaps[name]
	switch {
	case got == want && known:
		t.Errorf("%s: now %s as %s expects; remove it from the known gaps", name, got, c.suite)
	case got == want:
		c.conforming++
	case known:
		c.gapped++
	default:
		t.Errorf("%s: %s, %s expects %s; failed rules: %v", name, got, c.suite, want, failures)
	}
}

// finish reports known gaps that name no run and returns the totals.
func (c *conformance) finish(t *testing.T) (conforming, gapped int) {
	t.Helper()
	for name := range c.gaps {
		if !c.seen[name] {
			t.Errorf("%s known gap %s does not name a run", c.suite, name)
		}
	}
	t.Logf("%s: %d runs conform, %d known gaps", c.suite, c.conforming, c.gapped)
	return c.conforming, c.gapped
}
