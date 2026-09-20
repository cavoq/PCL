package crl

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"sort"
	"time"

	crlzcrypto "github.com/cavoq/PCL/internal/crl/zcrypto"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

type listFingerprint [sha256.Size]byte

type decodedList struct {
	list           *x509.RevocationList
	facts          crlzcrypto.RevocationListFacts
	decodeError    bool
	fingerprint    listFingerprint
	entries        entryIndex
	current        bool
	baseUsable     bool
	authentication *authenticationCache
}

func uniqueDecodedLists(lists []*x509.RevocationList) []decodedList {
	seen := make(map[listFingerprint]struct{}, len(lists))
	records := make([]decodedList, 0, len(lists))
	for _, list := range lists {
		if list == nil {
			continue
		}
		fingerprint := revocationListFingerprint(list)
		if _, duplicate := seen[fingerprint]; duplicate {
			continue
		}
		seen[fingerprint] = struct{}{}
		facts, err := crlzcrypto.DecodeRevocationListStrict(list)
		record := decodedList{
			list: list, facts: facts, decodeError: err != nil,
			fingerprint: fingerprint,
		}
		if err == nil {
			record.entries = prepareEntryIndex(record)
		}
		records = append(records, record)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if comparison := bytes.Compare(records[i].list.RawIssuer, records[j].list.RawIssuer); comparison != 0 {
			return comparison < 0
		}
		if comparison := integerExtensionCompare(records[i].facts.CRLNumber, records[j].facts.CRLNumber); comparison != 0 {
			return comparison > 0
		}
		if !records[i].list.ThisUpdate.Equal(records[j].list.ThisUpdate) {
			return records[i].list.ThisUpdate.After(records[j].list.ThisUpdate)
		}
		return bytes.Compare(records[i].fingerprint[:], records[j].fingerprint[:]) < 0
	})
	return records
}

func revocationListFingerprint(list *x509.RevocationList) listFingerprint {
	hash := sha256.New()
	encoder := fingerprintEncoder{writer: hash}
	encoder.bytes(fingerprintSchema, []byte("pcl.crl.record.v1"))
	encoder.bytes(fingerprintRaw, list.Raw)
	encoder.bytes(fingerprintRawTBS, list.RawTBSRevocationList)
	encoder.bytes(fingerprintSignature, list.Signature)
	encoder.integer(fingerprintSignatureAlgorithm, int64(list.SignatureAlgorithm))

	// Name matching uses the raw issuer only when both compared names have a
	// raw encoding. Retain the parsed form even when RawIssuer is present so
	// the identity also covers comparisons with manually constructed
	// certificates that have no RawSubject.
	encoder.boolean(fingerprintRawIssuerPresent, len(list.RawIssuer) > 0)
	encoder.bytes(fingerprintRawIssuer, list.RawIssuer)
	encoder.bytes(fingerprintIssuerFallback, []byte(list.Issuer.String()))
	encoder.timestamp(fingerprintThisUpdate, list.ThisUpdate)
	encoder.timestamp(fingerprintNextUpdate, list.NextUpdate)
	encoder.optionalBigInt(
		fingerprintNumberPresent,
		fingerprintNumberSign,
		fingerprintNumberMagnitude,
		list.Number,
	)
	encoder.count(fingerprintExtensionsCount, len(list.Extensions))
	for _, extension := range list.Extensions {
		writeExtensionFingerprint(encoder, extension)
	}
	encoder.count(fingerprintEntriesCount, len(list.RevokedCertificates))
	for _, entry := range list.RevokedCertificates {
		encoder.marker(fingerprintEntry)
		encoder.bytes(fingerprintEntryRaw, entry.Raw)
		encoder.optionalBigInt(
			fingerprintEntrySerialPresent,
			fingerprintEntrySerialSign,
			fingerprintEntrySerialMagnitude,
			entry.SerialNumber,
		)
		encoder.timestamp(fingerprintEntryRevocationTime, entry.RevocationTime)
		encoder.count(fingerprintEntryExtensionsCount, len(entry.Extensions))
		for _, extension := range entry.Extensions {
			writeExtensionFingerprint(encoder, extension)
		}
	}
	var result listFingerprint
	copy(result[:], hash.Sum(nil))
	return result
}

type fingerprintField byte

const (
	fingerprintSchema fingerprintField = iota + 1
	fingerprintRaw
	fingerprintRawTBS
	fingerprintSignature
	fingerprintSignatureAlgorithm
	fingerprintRawIssuerPresent
	fingerprintRawIssuer
	fingerprintIssuerFallback
	fingerprintThisUpdate
	fingerprintNextUpdate
	fingerprintNumberPresent
	fingerprintNumberSign
	fingerprintNumberMagnitude
	fingerprintExtensionsCount
	fingerprintEntriesCount
	fingerprintEntry
	fingerprintEntryRaw
	fingerprintEntrySerialPresent
	fingerprintEntrySerialSign
	fingerprintEntrySerialMagnitude
	fingerprintEntryRevocationTime
	fingerprintEntryExtensionsCount
	fingerprintExtension
	fingerprintExtensionOID
	fingerprintExtensionCritical
	fingerprintExtensionValue
)

type fingerprintEncoder struct {
	writer hashWriter
}

func (e fingerprintEncoder) marker(field fingerprintField) {
	e.bytes(field, nil)
}

func (e fingerprintEncoder) bytes(field fingerprintField, value []byte) {
	_, _ = e.writer.Write([]byte{byte(field)})
	writeHashPart(e.writer, value)
}

func (e fingerprintEncoder) boolean(field fingerprintField, value bool) {
	encoded := byte(0)
	if value {
		encoded = 1
	}
	e.bytes(field, []byte{encoded})
}

func (e fingerprintEncoder) integer(field fingerprintField, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	e.bytes(field, encoded[:])
}

func (e fingerprintEncoder) count(field fingerprintField, value int) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	e.bytes(field, encoded[:])
}

func (e fingerprintEncoder) timestamp(field fingerprintField, value time.Time) {
	e.bytes(field, []byte(value.UTC().Format(time.RFC3339Nano)))
}

func (e fingerprintEncoder) optionalBigInt(
	presentField, signField, magnitudeField fingerprintField,
	value *big.Int,
) {
	e.boolean(presentField, value != nil)
	if value == nil {
		return
	}
	e.integer(signField, int64(value.Sign()))
	e.bytes(magnitudeField, value.Bytes())
}

func writeExtensionFingerprint(encoder fingerprintEncoder, extension pkix.Extension) {
	encoder.marker(fingerprintExtension)
	encoder.bytes(fingerprintExtensionOID, []byte(extension.Id.String()))
	encoder.boolean(fingerprintExtensionCritical, extension.Critical)
	encoder.bytes(fingerprintExtensionValue, extension.Value)
}

type hashWriter interface{ Write([]byte) (int, error) }

func writeHashPart(writer hashWriter, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}
