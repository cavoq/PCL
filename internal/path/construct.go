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
}

// Construct builds a deterministic path from one of targets through the
// supplied intermediates to an explicit trust anchor. It performs only the
// name/signature work needed to rank issuer candidates; all RFC 5280 semantic
// decisions are left to Validate.
func Construct(targets, intermediates, trustAnchors []*cert.Info, maxDepth int) (Construction, error) {
	if len(targets) == 0 {
		return Construction{}, fmt.Errorf("no path targets provided")
	}
	pool := uniqueInfos(append(append([]*cert.Info(nil), intermediates...), trustAnchors...))
	cert.ResolveInheritedDSAParameters(targets, pool)
	if maxDepth <= 0 {
		maxDepth = len(pool) + 1
	}

	var best constructedCandidate
	for _, target := range uniqueInfos(targets) {
		if target == nil || target.Cert == nil {
			continue
		}
		candidate := constructFrom(target, pool, trustAnchors, maxDepth, nil)
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

func (candidate constructedCandidate) betterTargetThan(other constructedCandidate) bool {
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
	return compareChains(candidate.chain, other.chain) < 0
}

type constructedCandidate struct {
	chain             []*cert.Info
	anchor            *cert.Info
	invalidSignatures int
}

func (candidate constructedCandidate) betterThan(other constructedCandidate) bool {
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
	return compareChains(candidate.chain, other.chain) < 0
}

func constructFrom(
	current *cert.Info,
	pool, trustAnchors []*cert.Info,
	maxDepth int,
	chain []*cert.Info,
) constructedCandidate {
	chain = append(slices.Clone(chain), current)
	if anchor := matchingTrustAnchor(current, trustAnchors); anchor != nil {
		return constructedCandidate{chain: chain, anchor: anchor}
	}
	if len(chain) >= maxDepth {
		return constructedCandidate{chain: chain}
	}

	candidates := issuerCandidates(current, pool, chain, trustAnchors)
	best := constructedCandidate{chain: chain}
	for _, candidate := range candidates {
		next := constructFrom(candidate.info, pool, trustAnchors, maxDepth, chain)
		if !candidate.signatureValid {
			next.invalidSignatures++
		}
		if next.betterThan(best) {
			best = next
		}
	}
	return best
}

type issuerCandidate struct {
	info           *cert.Info
	anchor         bool
	signatureValid bool
	fingerprint    [sha256.Size]byte
}

func issuerCandidates(
	child *cert.Info,
	pool, chain, trustAnchors []*cert.Info,
) []issuerCandidate {
	var candidates []issuerCandidate
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
		candidates = append(candidates, issuerCandidate{
			info:           candidate,
			anchor:         matchingTrustAnchor(candidate, trustAnchors) != nil,
			signatureValid: cert.SignedBy(child.Cert, candidate.Cert),
			fingerprint:    sha256.Sum256(candidate.Cert.Raw),
		})
	}
	slices.SortFunc(candidates, func(left, right issuerCandidate) int {
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

func compareChains(left, right []*cert.Info) int {
	for index := 0; index < min(len(left), len(right)); index++ {
		leftFingerprint := sha256.Sum256(left[index].Cert.Raw)
		rightFingerprint := sha256.Sum256(right[index].Cert.Raw)
		if comparison := bytes.Compare(leftFingerprint[:], rightFingerprint[:]); comparison != 0 {
			return comparison
		}
	}
	return len(left) - len(right)
}
