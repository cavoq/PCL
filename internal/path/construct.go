package path

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/x509asn1"
)

// Construction is the deterministic result of path construction. Chain is
// ordered target-to-top and includes the trust anchor when one was reached.
// Validation remains a separate operation even when Anchored is true.
type Construction struct {
	Chain       []*cert.Info
	Anchored    bool
	TrustAnchor *cert.Info
	// Truncated reports that no anchored path exists and the search for the
	// best unanchored path stopped at its work budget. Chain is then the best
	// unanchored path found before the budget ran out.
	Truncated bool
}

// unanchoredSearchBudget bounds the number of partial paths the unanchored
// search extends per Construct call. Anchored paths are found without
// enumerating paths, so the budget only limits the choice of chain for inputs
// that cannot reach an anchor. Tests lower it.
var unanchoredSearchBudget = 1 << 16

// Construct builds a deterministic path from one of targets through the
// supplied intermediates to an explicit trust anchor. It performs only the
// name/signature work needed to rank issuer candidates; all RFC 5280 semantic
// decisions are left to Validate.
//
// Paths are ranked by reaching an anchor, then by fewer issuer signatures
// that do not verify, then anchored paths by fewer and unanchored paths by
// more certificates, then by the certificate fingerprints in path order.
func Construct(targets, intermediates, trustAnchors []*cert.Info, maxDepth int) (Construction, error) {
	if len(targets) == 0 {
		return Construction{}, fmt.Errorf("no path targets provided")
	}
	pool := uniqueInfos(append(append([]*cert.Info(nil), intermediates...), trustAnchors...))
	if maxDepth <= 0 {
		maxDepth = len(pool) + 1
	}
	search := newPathSearch(pool, trustAnchors, maxDepth)

	var best constructedCandidate
	for _, target := range uniqueInfos(targets) {
		if target == nil || target.Cert == nil {
			continue
		}
		candidate := search.bestAnchored(target)
		if candidate.anchor == nil {
			candidate = search.bestUnanchored(target, constructedCandidate{})
		}
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
		Truncated:   best.anchor == nil && search.truncated,
	}, nil
}

// alternativeSearchBudget bounds the partial paths Candidates extends, and
// alternativeLimit the anchored paths it returns. Tests lower them.
var (
	alternativeSearchBudget = 1 << 12
	alternativeLimit        = 64
)

// Candidates returns anchored paths from target through intermediates to an
// explicit trust anchor, best first in Construct's ranking, so a caller can
// fall back to another path when the best one fails validation (RFC 4158).
// Only issuers whose signature verifies are followed, since a path with an
// invalid signature never validates, and no certificate repeats. The search
// stops after a bounded amount of work and number of paths.
func Candidates(target *cert.Info, intermediates, trustAnchors []*cert.Info, maxDepth int) []Construction {
	if target == nil || target.Cert == nil {
		return nil
	}
	pool := uniqueInfos(append(append([]*cert.Info(nil), intermediates...), trustAnchors...))
	if maxDepth <= 0 {
		maxDepth = len(pool) + 1
	}
	search := newPathSearch(pool, trustAnchors, maxDepth)
	search.budget = alternativeSearchBudget

	var found []constructedCandidate
	var walk func(partial constructedCandidate)
	walk = func(partial constructedCandidate) {
		if len(found) >= alternativeLimit || len(partial.chain) >= search.maxDepth || search.budget == 0 {
			return
		}
		search.budget--
		current := partial.chain[len(partial.chain)-1]
		for _, issuer := range search.issuerCandidates(current) {
			if !issuer.signatureValid || containsCertificate(partial.chain, issuer.info) {
				continue
			}
			extended := partial.extend(issuer)
			if anchor := matchingTrustAnchor(issuer.info, search.trustAnchors); anchor != nil {
				extended.anchor = anchor
				found = append(found, extended)
				if len(found) >= alternativeLimit {
					return
				}
				continue
			}
			walk(extended)
		}
	}
	initial := search.start(target)
	if initial.anchor != nil {
		found = append(found, initial)
	} else {
		walk(initial)
	}

	slices.SortFunc(found, func(left, right constructedCandidate) int {
		switch {
		case left.betterThan(right):
			return -1
		case right.betterThan(left):
			return 1
		}
		return 0
	})
	constructions := make([]Construction, 0, len(found))
	for _, candidate := range found {
		constructions = append(constructions, Construction{
			Chain:       candidate.chain,
			Anchored:    true,
			TrustAnchor: candidate.anchor,
		})
	}
	return constructions
}

type constructedCandidate struct {
	chain             []*cert.Info
	fingerprints      [][sha256.Size]byte
	anchor            *cert.Info
	invalidSignatures int
}

func (candidate constructedCandidate) extend(issuer issuerCandidate) constructedCandidate {
	extended := constructedCandidate{
		chain:             append(slices.Clone(candidate.chain), issuer.info),
		fingerprints:      append(slices.Clone(candidate.fingerprints), issuer.fingerprint),
		invalidSignatures: candidate.invalidSignatures,
	}
	if !issuer.signatureValid {
		extended.invalidSignatures++
	}
	return extended
}

// betterThan ranks paths from the same target.
func (candidate constructedCandidate) betterThan(other constructedCandidate) bool {
	return candidate.ranksBefore(other, true)
}

// betterTargetThan ranks the best paths of different targets, where the
// longer path wins even when both are anchored.
func (candidate constructedCandidate) betterTargetThan(other constructedCandidate) bool {
	return candidate.ranksBefore(other, false)
}

func (candidate constructedCandidate) ranksBefore(other constructedCandidate, shorterAnchored bool) bool {
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
		if candidate.anchor != nil && shorterAnchored {
			return len(candidate.chain) < len(other.chain)
		}
		return len(candidate.chain) > len(other.chain)
	}
	return compareFingerprints(candidate.fingerprints, other.fingerprints) < 0
}

// pathSearch holds the facts every partial path of one Construct call
// reuses, so each issuer signature is verified at most once.
type pathSearch struct {
	pool         []*cert.Info
	trustAnchors []*cert.Info
	maxDepth     int
	issuers      map[*cert.Info][]issuerCandidate
	budget       int
	truncated    bool
}

func newPathSearch(pool, trustAnchors []*cert.Info, maxDepth int) *pathSearch {
	return &pathSearch{
		pool:         pool,
		trustAnchors: trustAnchors,
		maxDepth:     maxDepth,
		issuers:      make(map[*cert.Info][]issuerCandidate),
		budget:       unanchoredSearchBudget,
	}
}

func (search *pathSearch) start(target *cert.Info) constructedCandidate {
	return constructedCandidate{
		chain:        []*cert.Info{target},
		fingerprints: [][sha256.Size]byte{sha256.Sum256(target.Cert.Raw)},
		anchor:       matchingTrustAnchor(target, search.trustAnchors),
	}
}

// bestAnchored returns the best path from target to a trust anchor within
// maxDepth, or a candidate without anchor when none exists. It extends one
// best partial path per certificate and length. A path that revisits a
// certificate is worse than the same path without the cycle, so the best
// path found this way is the best path without repeated certificates.
func (search *pathSearch) bestAnchored(target *cert.Info) constructedCandidate {
	initial := search.start(target)
	if initial.anchor != nil {
		return initial
	}
	var best constructedCandidate
	frontier := map[*cert.Info]constructedCandidate{target: initial}
	for length := 1; length < search.maxDepth && len(frontier) > 0; length++ {
		next := make(map[*cert.Info]constructedCandidate)
		for child, partial := range frontier {
			// A longer anchored path only wins with fewer invalid signatures;
			// one of equal length can still win on fingerprints.
			if best.anchor != nil && (partial.invalidSignatures > best.invalidSignatures ||
				partial.invalidSignatures == best.invalidSignatures && len(partial.chain) >= len(best.chain)) {
				continue
			}
			for _, issuer := range search.issuerCandidates(child) {
				extended := partial.extend(issuer)
				if anchor := matchingTrustAnchor(issuer.info, search.trustAnchors); anchor != nil {
					extended.anchor = anchor
					if extended.betterThan(best) {
						best = extended
					}
					continue
				}
				current, seen := next[issuer.info]
				if !seen || extended.invalidSignatures < current.invalidSignatures ||
					extended.invalidSignatures == current.invalidSignatures &&
						compareFingerprints(extended.fingerprints, current.fingerprints) < 0 {
					next[issuer.info] = extended
				}
			}
		}
		frontier = next
	}
	return best
}

// bestUnanchored searches the paths without repeated certificates for the
// best one when no anchor is reachable. Longest-path ranking has no
// polynomial shortcut, so the search stops at the work budget.
func (search *pathSearch) bestUnanchored(target *cert.Info, partial constructedCandidate) constructedCandidate {
	if len(partial.chain) == 0 {
		partial = search.start(target)
	}
	if len(partial.chain) >= search.maxDepth {
		return partial
	}
	if search.budget == 0 {
		search.truncated = true
		return partial
	}
	search.budget--

	best := partial
	current := partial.chain[len(partial.chain)-1]
	for _, issuer := range search.issuerCandidates(current) {
		if containsCertificate(partial.chain, issuer.info) {
			continue
		}
		next := search.bestUnanchored(target, partial.extend(issuer))
		if next.betterThan(best) {
			best = next
		}
	}
	return best
}

type issuerCandidate struct {
	info           *cert.Info
	signatureValid bool
	fingerprint    [sha256.Size]byte
}

// issuerCandidates returns the pool certificates whose subject matches the
// child's issuer, other than the child itself. They are computed once per
// child.
func (search *pathSearch) issuerCandidates(child *cert.Info) []issuerCandidate {
	if candidates, ok := search.issuers[child]; ok {
		return candidates
	}
	var candidates []issuerCandidate
	for _, candidate := range search.pool {
		if candidate == nil || candidate.Cert == nil || cert.SameCertificate(child.Cert, candidate.Cert) ||
			!x509asn1.NamesMatchOrText(
				child.Cert.RawIssuer,
				candidate.Cert.RawSubject,
				child.Cert.Issuer.String(),
				candidate.Cert.Subject.String(),
			) {
			continue
		}
		candidates = append(candidates, issuerCandidate{
			info:           candidate,
			signatureValid: cert.SignedBy(child.Cert, candidate.Cert),
			fingerprint:    sha256.Sum256(candidate.Cert.Raw),
		})
	}
	// Verifying issuers first, then fingerprint order, makes a budgeted
	// search explore the most plausible paths first.
	slices.SortFunc(candidates, func(left, right issuerCandidate) int {
		if left.signatureValid != right.signatureValid {
			if left.signatureValid {
				return -1
			}
			return 1
		}
		return bytes.Compare(left.fingerprint[:], right.fingerprint[:])
	})
	search.issuers[child] = candidates
	return candidates
}

func matchingTrustAnchor(info *cert.Info, trustAnchors []*cert.Info) *cert.Info {
	if info == nil || info.Cert == nil {
		return nil
	}
	for _, anchor := range trustAnchors {
		if anchor != nil && anchor.Cert != nil && cert.SameCertificate(info.Cert, anchor.Cert) {
			return anchor
		}
	}
	return nil
}

func uniqueInfos(infos []*cert.Info) []*cert.Info {
	seen := cert.NewCertificateSet()
	result := make([]*cert.Info, 0, len(infos))
	for _, info := range infos {
		if info != nil && info.Cert != nil && seen.Add(info.Cert) {
			result = append(result, info)
		}
	}
	return result
}

func containsCertificate(infos []*cert.Info, candidate *cert.Info) bool {
	return slices.ContainsFunc(infos, func(info *cert.Info) bool {
		return info != nil && candidate != nil &&
			cert.SameCertificate(info.Cert, candidate.Cert)
	})
}

func compareFingerprints(left, right [][sha256.Size]byte) int {
	for index := 0; index < min(len(left), len(right)); index++ {
		if comparison := bytes.Compare(left[index][:], right[index][:]); comparison != 0 {
			return comparison
		}
	}
	return len(left) - len(right)
}
