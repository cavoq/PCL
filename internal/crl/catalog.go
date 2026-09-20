package crl

import (
	"bytes"
	"sort"
	"time"

	"github.com/zmap/zcrypto/x509"
)

// Catalog prepares a fixed collection of CRLs and signer candidates for
// repeated certificate assessments. The evaluation time, delta policy, and
// signer authorizer are bound when the catalog is built.
//
// A Catalog may be reused concurrently. Callers must not mutate the CRLs or
// certificates while assessments are running. A bound SignerAuthorizer must
// be deterministic for a given target, signer, and list; concurrent Catalog
// use also requires the authorizer to be concurrency-safe.
type Catalog struct {
	now             time.Time
	useDeltas       bool
	authorizeSigner SignerAuthorizer

	records         []decodedList
	malformed       []*decodedList
	complete        []completeRank
	completeCount   int
	maxCompleteRank int
	deltas          []*decodedList

	signers []preparedSigner
}

type completeRank struct {
	records []*decodedList
}

type completeCandidate struct {
	record *decodedList
	match  entryMatch
}

// NewCatalog decodes, deduplicates, indexes, and orders lists once for the
// supplied revocation context. Per-target signer authorization remains local
// to each AssessCertificate call.
func NewCatalog(
	lists []*x509.RevocationList,
	ctx RevocationContext,
) *Catalog {
	catalog := &Catalog{
		now:             ctx.Now,
		useDeltas:       ctx.UseDeltas,
		authorizeSigner: ctx.AuthorizeSigner,
		records:         uniqueDecodedLists(lists),
	}
	catalog.malformed = make([]*decodedList, 0, len(catalog.records))
	complete := make([]*decodedList, 0, len(catalog.records))
	catalog.deltas = make([]*decodedList, 0, len(catalog.records))

	for index := range catalog.records {
		record := &catalog.records[index]
		record.current = IsCurrentAt(record.list, ctx.Now)
		record.baseUsable = baseUsableWithDelta(record.list, ctx.Now)
		switch {
		case record.decodeError:
			catalog.malformed = append(catalog.malformed, record)
		case record.facts.DeltaCRLIndicator != nil:
			catalog.deltas = append(catalog.deltas, record)
		default:
			complete = append(complete, record)
		}
	}

	sortCompleteRecords(complete)
	catalog.complete = groupCompleteRanks(complete)
	catalog.completeCount = len(complete)
	for _, rank := range catalog.complete {
		catalog.maxCompleteRank = max(catalog.maxCompleteRank, len(rank.records))
	}
	sortDeltaRecords(catalog.deltas)

	catalog.signers = prepareSignerPool(ctx.Issuers)
	for index := range catalog.records {
		if !catalog.records[index].decodeError {
			catalog.records[index].authentication = &authenticationCache{}
		}
	}
	return catalog
}

func sortCompleteRecords(records []*decodedList) {
	sort.SliceStable(records, func(i, j int) bool {
		if comparison := integerExtensionCompare(
			records[i].facts.CRLNumber,
			records[j].facts.CRLNumber,
		); comparison != 0 {
			return comparison > 0
		}
		if !records[i].list.ThisUpdate.Equal(records[j].list.ThisUpdate) {
			return records[i].list.ThisUpdate.After(records[j].list.ThisUpdate)
		}
		return bytes.Compare(records[i].fingerprint[:], records[j].fingerprint[:]) < 0
	})
}

func groupCompleteRanks(records []*decodedList) []completeRank {
	ranks := make([]completeRank, 0, len(records))
	for _, record := range records {
		if len(ranks) == 0 || !sameCompleteRank(
			ranks[len(ranks)-1].records[0],
			record,
		) {
			ranks = append(ranks, completeRank{})
		}
		last := len(ranks) - 1
		ranks[last].records = append(ranks[last].records, record)
	}
	return ranks
}

func sameCompleteRank(first, second *decodedList) bool {
	return integerExtensionCompare(
		first.facts.CRLNumber,
		second.facts.CRLNumber,
	) == 0 && first.list.ThisUpdate.Equal(second.list.ThisUpdate)
}

func sortDeltaRecords(records []*decodedList) {
	sort.SliceStable(records, func(i, j int) bool {
		if !records[i].list.ThisUpdate.Equal(records[j].list.ThisUpdate) {
			return records[i].list.ThisUpdate.After(records[j].list.ThisUpdate)
		}
		if comparison := integerExtensionCompare(
			records[i].facts.CRLNumber,
			records[j].facts.CRLNumber,
		); comparison != 0 {
			return comparison > 0
		}
		return bytes.Compare(records[i].fingerprint[:], records[j].fingerprint[:]) < 0
	})
}

// completeCandidates preserves complete-list rank ordering while placing a
// valid revocation for this target first only among otherwise equal records.
func (catalog *Catalog) completeCandidates(
	target targetEntryKey,
) []completeCandidate {
	ordered := make([]completeCandidate, 0, catalog.completeCount)
	scratch := make([]completeCandidate, 0, catalog.maxCompleteRank)
	for _, rank := range catalog.complete {
		scratch = scratch[:0]
		for _, record := range rank.records {
			scratch = append(scratch, completeCandidate{
				record: record,
				match:  record.entries.findTarget(target),
			})
		}
		for _, candidate := range scratch {
			if candidate.match.found && !candidate.match.invalid &&
				!candidate.match.removesFromCRL() {
				ordered = append(ordered, candidate)
			}
		}
		for _, candidate := range scratch {
			if !candidate.match.found || candidate.match.invalid ||
				candidate.match.removesFromCRL() {
				ordered = append(ordered, candidate)
			}
		}
	}
	return ordered
}
