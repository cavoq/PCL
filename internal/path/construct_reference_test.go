package path

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/testpki"
	"github.com/cavoq/PCL/internal/x509asn1"
)

// TestConstructMatchesExhaustiveSearch compares Construct with the exhaustive
// depth-first search it replaced, on random certificate graphs with
// same-name keys, cross-certification cycles, self-signed roots, anchors in
// any position and depth limits.
func TestConstructMatchesExhaustiveSearch(t *testing.T) {
	const names, keysPerName, certificates = 4, 2, 24
	random := rand.New(rand.NewPCG(1, 2))

	type identity struct{ name, key int }
	keys := make(map[identity]crypto.Signer)
	bases := make(map[identity]*testpki.Certificate)
	var pool []*cert.Info
	serial := int64(0)
	for name := range names {
		for key := range keysPerName {
			id := identity{name, key}
			keys[id] = testpki.ECDSAKey(t)
			serial++
			bases[id] = testpki.IssueWithKey(t, fmt.Sprintf("Name %d", name), keys[id], nil,
				testpki.CA(), testpki.Serial(serial))
			pool = append(pool, &cert.Info{Cert: bases[id].Cert})
		}
	}
	for range certificates {
		subject := identity{random.IntN(names), random.IntN(keysPerName)}
		issuer := identity{random.IntN(names), random.IntN(keysPerName)}
		serial++
		issued := testpki.IssueWithKey(t, fmt.Sprintf("Name %d", subject.name), keys[subject],
			bases[issuer], testpki.CA(), testpki.Serial(serial))
		pool = append(pool, &cert.Info{Cert: issued.Cert})
	}

	pick := func(from []*cert.Info, probability float64) []*cert.Info {
		var picked []*cert.Info
		for _, info := range from {
			if random.Float64() < probability {
				picked = append(picked, info)
			}
		}
		return picked
	}
	anchoredRuns := 0
	for run := range 500 {
		intermediates := pick(pool, 0.7)
		anchors := pick(pool, 0.15)
		targets := []*cert.Info{pool[random.IntN(len(pool))]}
		if random.IntN(4) == 0 {
			targets = append(targets, pool[random.IntN(len(pool))])
		}
		// The exhaustive oracle is exponential without a depth limit.
		maxDepth := 1 + random.IntN(5)

		want, wantErr := referenceConstruct(targets, intermediates, anchors, maxDepth)
		got, gotErr := Construct(targets, intermediates, anchors, maxDepth)
		if (wantErr == nil) != (gotErr == nil) || got.Anchored != want.Anchored ||
			got.TrustAnchor != want.TrustAnchor || !slices.Equal(got.Chain, want.Chain) || got.Truncated {
			t.Fatalf("run %d: Construct = %+v, %v; exhaustive search = %+v, %v", run, got, gotErr, want, wantErr)
		}
		if got.Anchored {
			anchoredRuns++
		}
	}
	t.Logf("%d of 500 runs reached an anchor", anchoredRuns)
	if anchoredRuns < 50 {
		t.Fatalf("only %d of 500 runs reached an anchor", anchoredRuns)
	}
}

// referenceConstruct is the exhaustive depth-first path construction that
// Construct replaced, kept verbatim as a test oracle.
func referenceConstruct(targets, intermediates, trustAnchors []*cert.Info, maxDepth int) (Construction, error) {
	if len(targets) == 0 {
		return Construction{}, fmt.Errorf("no path targets provided")
	}
	pool := uniqueInfos(append(append([]*cert.Info(nil), intermediates...), trustAnchors...))
	if maxDepth <= 0 {
		maxDepth = len(pool) + 1
	}

	var best referenceCandidate
	for _, target := range uniqueInfos(targets) {
		if target == nil || target.Cert == nil {
			continue
		}
		candidate := referenceFrom(target, pool, trustAnchors, maxDepth, nil)
		if candidate.betterTargetThan(best) {
			best = candidate
		}
	}
	if len(best.chain) == 0 {
		return Construction{}, fmt.Errorf("no usable path target provided")
	}
	return Construction{
		Chain:       best.chain,
		Anchored:    best.anchor != nil,
		TrustAnchor: best.anchor,
	}, nil
}

func (candidate referenceCandidate) betterTargetThan(other referenceCandidate) bool {
	if len(candidate.chain) == 0 {
		return false
	}
	if len(other.chain) == 0 {
		return true
	}
	if (candidate.anchor != nil) != (other.anchor != nil) {
		return candidate.anchor != nil
	}
	if candidate.invalidSignatures != other.invalidSignatures {
		return candidate.invalidSignatures < other.invalidSignatures
	}
	if len(candidate.chain) != len(other.chain) {
		return len(candidate.chain) > len(other.chain)
	}
	return referenceCompareChains(candidate.chain, other.chain) < 0
}

type referenceCandidate struct {
	chain             []*cert.Info
	anchor            *cert.Info
	invalidSignatures int
}

func (candidate referenceCandidate) betterThan(other referenceCandidate) bool {
	if len(candidate.chain) == 0 {
		return false
	}
	if len(other.chain) == 0 {
		return true
	}
	if (candidate.anchor != nil) != (other.anchor != nil) {
		return candidate.anchor != nil
	}
	if candidate.invalidSignatures != other.invalidSignatures {
		return candidate.invalidSignatures < other.invalidSignatures
	}
	if len(candidate.chain) != len(other.chain) {
		if candidate.anchor != nil {
			return len(candidate.chain) < len(other.chain)
		}
		return len(candidate.chain) > len(other.chain)
	}
	return referenceCompareChains(candidate.chain, other.chain) < 0
}

func referenceFrom(
	current *cert.Info,
	pool, trustAnchors []*cert.Info,
	maxDepth int,
	chain []*cert.Info,
) referenceCandidate {
	chain = append(slices.Clone(chain), current)
	if anchor := matchingTrustAnchor(current, trustAnchors); anchor != nil {
		return referenceCandidate{chain: chain, anchor: anchor}
	}
	if len(chain) >= maxDepth {
		return referenceCandidate{chain: chain}
	}

	candidates := referenceIssuerCandidates(current, pool, chain, trustAnchors)
	best := referenceCandidate{chain: chain}
	for _, candidate := range candidates {
		next := referenceFrom(candidate.info, pool, trustAnchors, maxDepth, chain)
		if !candidate.signatureValid {
			next.invalidSignatures++
		}
		if next.betterThan(best) {
			best = next
		}
	}
	return best
}

type referenceIssuer struct {
	info           *cert.Info
	anchor         bool
	signatureValid bool
	fingerprint    [sha256.Size]byte
}

func referenceIssuerCandidates(
	child *cert.Info,
	pool, chain, trustAnchors []*cert.Info,
) []referenceIssuer {
	var candidates []referenceIssuer
	for _, candidate := range pool {
		if candidate == nil || candidate.Cert == nil || containsCertificate(chain, candidate) ||
			!x509asn1.NamesMatchOrText(
				child.Cert.RawIssuer,
				candidate.Cert.RawSubject,
				child.Cert.Issuer.String(),
				candidate.Cert.Subject.String(),
			) {
			continue
		}
		candidates = append(candidates, referenceIssuer{
			info:           candidate,
			anchor:         matchingTrustAnchor(candidate, trustAnchors) != nil,
			signatureValid: cert.SignedBy(child.Cert, candidate.Cert),
			fingerprint:    sha256.Sum256(candidate.Cert.Raw),
		})
	}
	slices.SortFunc(candidates, func(left, right referenceIssuer) int {
		if left.signatureValid != right.signatureValid {
			if left.signatureValid {
				return -1
			}
			return 1
		}
		if left.anchor != right.anchor {
			if left.anchor {
				return -1
			}
			return 1
		}
		return bytes.Compare(left.fingerprint[:], right.fingerprint[:])
	})
	return candidates
}

func referenceCompareChains(left, right []*cert.Info) int {
	for index := 0; index < min(len(left), len(right)); index++ {
		leftFingerprint := sha256.Sum256(left[index].Cert.Raw)
		rightFingerprint := sha256.Sum256(right[index].Cert.Raw)
		if comparison := bytes.Compare(leftFingerprint[:], rightFingerprint[:]); comparison != 0 {
			return comparison
		}
	}
	return len(left) - len(right)
}
