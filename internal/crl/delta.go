package crl

import (
	"bytes"
	"time"

	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
)

type deltaDecision struct {
	selected *decodedList
}

func (run *assessmentRun) selectCompatibleDelta(
	base *decodedList,
	baseSigner *preparedSigner,
) *decodedList {
	if decision, found := run.deltaDecisions[base]; found {
		return decision.selected
	}
	var selected *decodedList
	for _, delta := range run.catalog.deltas {
		if len(delta.facts.UnsupportedCriticalExtensionOIDs) > 0 ||
			delta.facts.FreshestCRL != nil ||
			!delta.current ||
			!deltaCompatibleWithBase(base, delta) {
			continue
		}
		deltaSigner, _ := run.authenticatedSigner(delta)
		if !sameSignerPublicKey(baseSigner, deltaSigner) {
			continue
		}
		selected = delta
		break
	}
	run.deltaDecisions[base] = deltaDecision{selected: selected}
	return selected
}

func deltaCompatibleWithBase(base, delta *decodedList) bool {
	if !namesEqual(
		base.list.RawIssuer,
		delta.list.RawIssuer,
		base.list.Issuer.String(),
		delta.list.Issuer.String(),
	) {
		return false
	}
	if !idpEqual(base.facts.IssuingDistributionPoint, delta.facts.IssuingDistributionPoint) ||
		!authorityKeyIdentifiersEqual(base.facts.AuthorityKeyIdentifier, delta.facts.AuthorityKeyIdentifier) ||
		base.facts.CRLNumber == nil || delta.facts.CRLNumber == nil ||
		delta.facts.DeltaCRLIndicator == nil {
		return false
	}
	return integerExtensionCompare(base.facts.CRLNumber, delta.facts.DeltaCRLIndicator) >= 0 &&
		integerExtensionCompare(base.facts.CRLNumber, delta.facts.CRLNumber) < 0
}

func idpEqual(
	first, second *x509ext.IssuingDistributionPointFacts,
) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return bytes.Equal(first.RawDER, second.RawDER)
}

func authorityKeyIdentifiersEqual(
	first, second *x509ext.AuthorityKeyIdentifierFacts,
) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return bytes.Equal(first.RawDER, second.RawDER)
}

func integerExtensionCompare(
	first, second *x509ext.IntegerExtensionFacts,
) int {
	if first == nil || second == nil {
		switch {
		case first == nil && second == nil:
			return 0
		case first == nil:
			return -1
		default:
			return 1
		}
	}
	return compareNonNegativeIntegers(first.Value, second.Value)
}

func compareNonNegativeIntegers(first, second x509ext.NonNegativeInteger) int {
	firstContent := bytes.TrimLeft(first.Content, "\x00")
	secondContent := bytes.TrimLeft(second.Content, "\x00")
	if len(firstContent) != len(secondContent) {
		if len(firstContent) < len(secondContent) {
			return -1
		}
		return 1
	}
	return bytes.Compare(firstContent, secondContent)
}

func baseUsableWithDelta(list *x509.RevocationList, now time.Time) bool {
	return list != nil && !now.Before(list.ThisUpdate) &&
		!list.ThisUpdate.IsZero() && !list.NextUpdate.IsZero() &&
		list.NextUpdate.After(list.ThisUpdate)
}
