package path

import (
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

// TestCandidatesMatchExhaustiveEnumeration compares Candidates with every
// anchored path without repeated certificates whose signatures verify, on
// random certificate graphs, and checks that its first path is the one
// Construct selects whenever that path's signatures all verify.
func TestCandidatesMatchExhaustiveEnumeration(t *testing.T) {
	const names, keysPerName, certificates = 4, 2, 24
	random := rand.New(rand.NewPCG(3, 4))

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

	pick := func(probability float64) []*cert.Info {
		var picked []*cert.Info
		for _, info := range pool {
			if random.Float64() < probability {
				picked = append(picked, info)
			}
		}
		return picked
	}
	multiple, matchedConstruct := 0, 0
	for run := range 300 {
		intermediates := pick(0.7)
		anchors := pick(0.15)
		target := pool[random.IntN(len(pool))]
		maxDepth := 1 + random.IntN(5)

		got := Candidates(target, intermediates, anchors, maxDepth)
		want := referenceCandidates(target, intermediates, anchors, maxDepth)
		if len(got) != len(want) {
			t.Fatalf("run %d: %d candidates, exhaustive enumeration finds %d", run, len(got), len(want))
		}
		for index := range got {
			if !got[index].Anchored || got[index].TrustAnchor == nil {
				t.Fatalf("run %d: candidate %d is not anchored", run, index)
			}
			if !slices.ContainsFunc(want, func(chain []*cert.Info) bool { return slices.Equal(chain, got[index].Chain) }) {
				t.Fatalf("run %d: candidate %d is not an anchored signature-valid path", run, index)
			}
			if index > 0 && candidateRank(got[index], anchors).betterThan(candidateRank(got[index-1], anchors)) {
				t.Fatalf("run %d: candidate %d ranks before candidate %d", run, index, index-1)
			}
		}
		if len(got) > 1 {
			multiple++
		}

		construction, err := Construct([]*cert.Info{target}, intermediates, anchors, maxDepth)
		if err == nil && construction.Anchored && signaturesVerify(construction.Chain) {
			if len(got) == 0 || !slices.Equal(got[0].Chain, construction.Chain) {
				t.Fatalf("run %d: first candidate differs from the constructed path", run)
			}
			matchedConstruct++
		}
	}
	if multiple < 20 || matchedConstruct < 20 {
		t.Fatalf("weak coverage: %d runs with several candidates, %d compared with Construct", multiple, matchedConstruct)
	}
}

func TestCandidatesStopAtTheirBounds(t *testing.T) {
	leaf, intermediates, roots := crossCertifiedMesh(t, 3, 4)
	if got := Candidates(leaf, intermediates, roots, 0); len(got) != alternativeLimit {
		t.Fatalf("3x4 mesh: %d candidates, want the limit %d", len(got), alternativeLimit)
	}

	limit, budget := alternativeLimit, alternativeSearchBudget
	t.Cleanup(func() { alternativeLimit, alternativeSearchBudget = limit, budget })
	alternativeLimit, alternativeSearchBudget = 1000, 3
	if got := Candidates(leaf, intermediates, roots, 0); len(got) != 0 {
		t.Fatalf("a budget below the path length found %d candidates", len(got))
	}
}

func referenceCandidates(target *cert.Info, intermediates, anchors []*cert.Info, maxDepth int) [][]*cert.Info {
	pool := uniqueInfos(append(append([]*cert.Info(nil), intermediates...), anchors...))
	if matchingTrustAnchor(target, anchors) != nil {
		return [][]*cert.Info{{target}}
	}
	var found [][]*cert.Info
	var walk func(chain []*cert.Info)
	walk = func(chain []*cert.Info) {
		if len(chain) >= maxDepth {
			return
		}
		child := chain[len(chain)-1]
		for _, issuer := range pool {
			if cert.SameCertificate(child.Cert, issuer.Cert) || containsCertificate(chain, issuer) ||
				!x509asn1.NamesMatchOrText(child.Cert.RawIssuer, issuer.Cert.RawSubject,
					child.Cert.Issuer.String(), issuer.Cert.Subject.String()) ||
				!cert.SignedBy(child.Cert, issuer.Cert) {
				continue
			}
			extended := append(slices.Clone(chain), issuer)
			if matchingTrustAnchor(issuer, anchors) != nil {
				found = append(found, extended)
				continue
			}
			walk(extended)
		}
	}
	walk([]*cert.Info{target})
	return found
}

func candidateRank(construction Construction, anchors []*cert.Info) constructedCandidate {
	search := newPathSearch(nil, anchors, len(construction.Chain)+1)
	candidate := search.start(construction.Chain[0])
	for _, info := range construction.Chain[1:] {
		candidate = candidate.extend(issuerCandidate{info: info, signatureValid: true, fingerprint: sha256.Sum256(info.Cert.Raw)})
	}
	candidate.anchor = construction.TrustAnchor
	return candidate
}

func signaturesVerify(chain []*cert.Info) bool {
	for index := 0; index+1 < len(chain); index++ {
		if !cert.SignedBy(chain[index].Cert, chain[index+1].Cert) {
			return false
		}
	}
	return true
}
