package crl

import (
	"math/big"
	"time"

	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
)

type entryMatch struct {
	found          bool
	invalid        bool
	index          int
	reasonCode     int
	revocationTime time.Time
}

// entryIndex is an immutable snapshot of the entries in one decoded CRL.  An
// entry is addressed by the exact DER encoding of its effective certificate
// issuer and its signed serial number.  Keeping the serial sign separate is
// important for manually constructed inputs: big.Int.Bytes reports only the
// magnitude, so +N and -N would otherwise alias.
type entryIndex struct {
	byCertificate         map[entryKey]indexedEntry
	issuerChainInvalid    bool
	semanticInvalid       bool
	containsRemoveFromCRL bool
}

type entryKey struct {
	issuer entryIssuerKey
	serial entrySerialKey
}

type targetEntryKey struct {
	key   entryKey
	valid bool
}

type entryIssuerKey string

type entrySerialKey struct {
	sign      int
	magnitude string
}

type indexedEntry struct {
	match     entryMatch
	duplicate bool
}

// prepareEntryIndex resolves certificateIssuer inheritance once for the
// entire list.  certificateIssuer applies to the entry carrying it and is
// inherited by following entries until another certificateIssuer replaces
// it.  Multiple directoryName values address the same entry under multiple
// keys; repeated copies of one directoryName within the same extension do not
// make that entry a duplicate.
func prepareEntryIndex(record decodedList) entryIndex {
	index := entryIndex{
		byCertificate: make(map[entryKey]indexedEntry, len(record.facts.Entries)),
	}

	var rawListIssuer []byte
	if record.list != nil {
		rawListIssuer = record.list.RawIssuer
	}
	currentIssuers := []entryIssuerKey{entryIssuerKey(string(rawListIssuer))}
	idp := record.facts.IssuingDistributionPoint
	indirect := idp != nil && idp.IndirectCRL
	reasonPartitioned := idp != nil && idp.OnlySomeReasons != nil

	for position, entry := range record.facts.Entries {
		if len(entry.UnsupportedCriticalExtensionOIDs) > 0 {
			index.semanticInvalid = true
		}
		currentIssuers = index.inheritIssuers(entry, currentIssuers, indirect)
		index.noteReasonCode(entry, reasonPartitioned)

		serial, present := newEntrySerialKey(entry.SerialNumber)
		if !present {
			continue
		}
		reason := 0
		if entry.ReasonCode != nil {
			reason = int(entry.ReasonCode.Value)
		}
		index.add(currentIssuers, serial, entryMatch{
			found:          true,
			index:          position,
			reasonCode:     reason,
			revocationTime: entry.RevocationTime,
		})
	}

	return index
}

// inheritIssuers returns the issuers that address entry and the entries
// after it. A certificateIssuer outside an indirect CRL, or one without a
// directoryName, invalidates the issuer chain for the rest of the list.
func (index *entryIndex) inheritIssuers(
	entry x509ext.EntryFacts,
	current []entryIssuerKey,
	indirect bool,
) []entryIssuerKey {
	if entry.CertificateIssuer == nil {
		return current
	}
	issuers := directoryNameIssuerKeys(entry.CertificateIssuer.Names)
	if !indirect || len(issuers) == 0 {
		index.issuerChainInvalid = true
		index.semanticInvalid = true
		return nil
	}
	return issuers
}

// noteReasonCode records list-wide facts carried by an entry reasonCode:
// unspecified is not allowed in a reason-partitioned CRL, and removeFromCRL
// marks delta semantics.
func (index *entryIndex) noteReasonCode(entry x509ext.EntryFacts, reasonPartitioned bool) {
	if entry.ReasonCode == nil {
		return
	}
	if reasonPartitioned && entry.ReasonCode.Value == x509ext.CRLReasonUnspecified {
		index.semanticInvalid = true
	}
	if entry.ReasonCode.Value == x509ext.CRLReasonRemoveFromCRL {
		index.containsRemoveFromCRL = true
	}
}

// add registers match under every issuer key. A second entry for the same
// key keeps the first match and marks it duplicate.
func (index *entryIndex) add(issuers []entryIssuerKey, serial entrySerialKey, match entryMatch) {
	for _, issuer := range issuers {
		key := entryKey{issuer: issuer, serial: serial}
		if indexed, duplicate := index.byCertificate[key]; duplicate {
			indexed.duplicate = true
			index.byCertificate[key] = indexed
			continue
		}
		index.byCertificate[key] = indexedEntry{match: match}
	}
}

func directoryNameIssuerKeys(names []x509ext.GeneralName) []entryIssuerKey {
	seen := make(map[entryIssuerKey]struct{}, len(names))
	issuers := make([]entryIssuerKey, 0, len(names))
	for _, name := range names {
		if name.Tag != 4 {
			continue
		}
		issuer := entryIssuerKey(string(name.RawValue))
		if _, duplicate := seen[issuer]; duplicate {
			continue
		}
		seen[issuer] = struct{}{}
		issuers = append(issuers, issuer)
	}
	return issuers
}

func newEntrySerialKey(serial *big.Int) (entrySerialKey, bool) {
	if serial == nil {
		return entrySerialKey{}, false
	}
	return entrySerialKey{
		sign:      serial.Sign(),
		magnitude: string(serial.Bytes()),
	}, true
}

func newTargetEntryKey(certificate *x509.Certificate) targetEntryKey {
	if certificate == nil {
		return targetEntryKey{}
	}
	serial, present := newEntrySerialKey(certificate.SerialNumber)
	if !present {
		return targetEntryKey{}
	}
	return targetEntryKey{
		key: entryKey{
			issuer: entryIssuerKey(string(certificate.RawIssuer)),
			serial: serial,
		},
		valid: true,
	}
}

// find returns a target-specific duplicate as invalid.  Duplicates belonging
// only to another issuer/serial pair do not poison this lookup.
func (index entryIndex) find(certificate *x509.Certificate) entryMatch {
	return index.findTarget(newTargetEntryKey(certificate))
}

func (index entryIndex) findTarget(target targetEntryKey) entryMatch {
	if !target.valid {
		return entryMatch{}
	}
	if index.issuerChainInvalid {
		return entryMatch{invalid: true}
	}
	indexed, present := index.byCertificate[target.key]
	if !present {
		return entryMatch{}
	}
	if indexed.duplicate {
		return entryMatch{invalid: true}
	}
	return indexed.match
}

// invalidFor reports the list-wide entry semantics that make the list
// unusable in its selected role.  removeFromCRL is valid in a delta CRL but
// invalid in a complete CRL.
func (index entryIndex) invalidFor(delta bool) bool {
	return index.semanticInvalid || (!delta && index.containsRemoveFromCRL)
}

func (m entryMatch) revocation(
	base, delta *x509.RevocationList,
) *Revocation {
	return &Revocation{
		CRL: base, Delta: delta, EntryIndex: m.index,
		ReasonCode: m.reasonCode, RevocationTime: m.revocationTime,
	}
}

func (m entryMatch) removesFromCRL() bool {
	return m.reasonCode == int(x509ext.CRLReasonRemoveFromCRL)
}
