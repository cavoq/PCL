package crl

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"sync"

	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
)

type preparedSigner struct {
	certificate      *x509.Certificate
	publicKeyDER     []byte
	publicKeyKnown   bool
	crlSignPermitted bool
}

type preparedAuthentication struct {
	eligible           []*preparedSigner
	sawVerifying       bool
	sawKeyUsageFailure bool
}

type authenticationCache struct {
	once  sync.Once
	value preparedAuthentication
}

type signerDecision struct {
	signer    *preparedSigner
	rejection EvidenceRejection
}

type orderedSigner struct {
	certificate *x509.Certificate
	orderKey    [sha256.Size]byte
}

// prepareSignerPool establishes one deterministic candidate order and caches
// signer properties that do not depend on the target certificate or CRL.
func prepareSignerPool(certificates []*x509.Certificate) []preparedSigner {
	ordered := make([]orderedSigner, 0, len(certificates))
	for _, certificate := range certificates {
		ordered = append(ordered, orderedSigner{
			certificate: certificate,
			orderKey:    syntheticSignerOrderKey(certificate),
		})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		left, right := ordered[i].certificate, ordered[j].certificate
		if left == nil {
			return false
		}
		if right == nil {
			return true
		}
		if comparison := bytes.Compare(left.Raw, right.Raw); comparison != 0 {
			return comparison < 0
		}
		if len(left.Raw) > 0 {
			return false
		}
		return bytes.Compare(ordered[i].orderKey[:], ordered[j].orderKey[:]) < 0
	})

	prepared := make([]preparedSigner, 0, len(ordered))
	for _, candidate := range ordered {
		if candidate.certificate == nil {
			continue
		}
		publicKeyDER, publicKeyKnown := signerPublicKeyDER(candidate.certificate)
		prepared = append(prepared, preparedSigner{
			certificate:      candidate.certificate,
			publicKeyDER:     publicKeyDER,
			publicKeyKnown:   publicKeyKnown,
			crlSignPermitted: crlSignUsagePermits(candidate.certificate),
		})
	}
	return prepared
}

func prepareAuthentication(
	record *decodedList,
	signers []preparedSigner,
) preparedAuthentication {
	var authentication preparedAuthentication
	if record == nil || record.list == nil {
		return authentication
	}
	for index := range signers {
		candidate := &signers[index]
		if !certSubjectMatchesCRLIssuer(candidate.certificate, record.list) ||
			!authorityKeyIdentifierMatches(
				candidate.certificate,
				record.facts.AuthorityKeyIdentifier,
			) ||
			!certVerifiesCRLSignature(candidate.certificate, record.list) {
			continue
		}
		authentication.sawVerifying = true
		if !candidate.crlSignPermitted {
			authentication.sawKeyUsageFailure = true
			continue
		}
		authentication.eligible = append(authentication.eligible, candidate)
	}
	return authentication
}

func (run *assessmentRun) authenticatedSigner(
	record *decodedList,
) (*preparedSigner, EvidenceRejection) {
	if decision, found := run.signerDecisions[record]; found {
		return decision.signer, decision.rejection
	}
	authentication := run.catalog.authenticationFor(record)
	decision := signerDecision{rejection: EvidenceSignerUnavailable}
	for _, candidate := range authentication.eligible {
		if run.catalog.authorizeSigner != nil &&
			!run.catalog.authorizeSigner.AuthorizeCRLSigner(
				run.target,
				candidate.certificate,
				record.list,
			) {
			continue
		}
		decision.signer = candidate
		decision.rejection = EvidenceAccepted
		break
	}
	if decision.signer == nil {
		switch {
		case authentication.sawKeyUsageFailure:
			decision.rejection = EvidenceSignerKeyUsage
		case authentication.sawVerifying && run.catalog.authorizeSigner != nil:
			decision.rejection = EvidenceSignerUnauthorized
		}
	}
	run.signerDecisions[record] = decision
	return decision.signer, decision.rejection
}

func (catalog *Catalog) authenticationFor(
	record *decodedList,
) preparedAuthentication {
	if catalog == nil || record == nil || record.authentication == nil {
		return preparedAuthentication{}
	}
	record.authentication.once.Do(func() {
		record.authentication.value = prepareAuthentication(record, catalog.signers)
	})
	return record.authentication.value
}

func signerPublicKeyDER(certificate *x509.Certificate) ([]byte, bool) {
	if certificate == nil {
		return nil, false
	}
	if len(certificate.RawSubjectPublicKeyInfo) > 0 {
		return append([]byte(nil), certificate.RawSubjectPublicKeyInfo...), true
	}
	if certificate.PublicKey == nil {
		return nil, false
	}
	encoded, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, false
	}
	return encoded, true
}

func sameSignerPublicKey(first, second *preparedSigner) bool {
	return first != nil && second != nil &&
		first.publicKeyKnown && second.publicKeyKnown &&
		bytes.Equal(first.publicKeyDER, second.publicKeyDER)
}

func syntheticSignerOrderKey(certificate *x509.Certificate) [sha256.Size]byte {
	if certificate == nil {
		return [sha256.Size]byte{}
	}
	hash := sha256.New()
	writeSignerOrderPart(hash, 1, certificate.RawSubject)
	writeSignerOrderPart(hash, 2, []byte(certificate.Subject.String()))
	writeSignerOrderPart(hash, 3, certificate.RawIssuer)
	writeSignerOrderPart(hash, 4, []byte(certificate.Issuer.String()))
	if certificate.SerialNumber == nil {
		writeSignerOrderPart(hash, 5, nil)
	} else {
		writeSignerOrderPart(hash, 6, []byte(certificate.SerialNumber.String()))
	}
	publicKeyDER, publicKeyKnown := signerPublicKeyDER(certificate)
	if publicKeyKnown {
		writeSignerOrderPart(hash, 7, publicKeyDER)
	} else {
		writeSignerOrderPart(hash, 8, nil)
	}
	writeSignerOrderPart(hash, 9, certificate.SubjectKeyId)
	var properties [8]byte
	binary.BigEndian.PutUint64(properties[:], uint64(certificate.KeyUsage))
	writeSignerOrderPart(hash, 10, properties[:])
	writeSignerOrderPart(hash, 11, certificate.RawTBSCertificate)
	writeSignerOrderPart(hash, 12, certificate.Signature)
	for _, extension := range certificate.Extensions {
		writeSignerOrderPart(hash, 13, []byte(extension.Id.String()))
		critical := byte(0)
		if extension.Critical {
			critical = 1
		}
		writeSignerOrderPart(hash, 14, []byte{critical})
		writeSignerOrderPart(hash, 15, extension.Value)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func writeSignerOrderPart(writer hashWriter, field byte, value []byte) {
	_, _ = writer.Write([]byte{field})
	writeHashPart(writer, value)
}

func authorityKeyIdentifierMatches(
	certificate *x509.Certificate,
	identifier *x509ext.AuthorityKeyIdentifierFacts,
) bool {
	if identifier == nil {
		return true
	}
	matched := false
	if len(identifier.KeyIdentifier) > 0 {
		if len(certificate.SubjectKeyId) == 0 ||
			!bytes.Equal(certificate.SubjectKeyId, identifier.KeyIdentifier) {
			return false
		}
		matched = true
	}
	if identifier.SerialNumber != nil {
		if certificate.SerialNumber == nil ||
			!nonNegativeIntegerMatches(*identifier.SerialNumber, certificate.SerialNumber.Bytes()) ||
			!generalNamesContainDirectoryName(identifier.AuthorityIssuer, certificate.RawIssuer) {
			return false
		}
		matched = true
	}
	return matched
}

func nonNegativeIntegerMatches(integer x509ext.NonNegativeInteger, magnitude []byte) bool {
	return bytes.Equal(
		bytes.TrimLeft(integer.Content, "\x00"),
		bytes.TrimLeft(magnitude, "\x00"),
	)
}

func crlSignUsagePermits(certificate *x509.Certificate) bool {
	if certificate == nil {
		return true
	}
	match := x509ext.NewExtensionIndex(certificate.Extensions).Lookup(oid.KeyUsage)
	if !match.Present() {
		return true
	}
	extension, unique := match.Extension()
	if !unique {
		return false
	}
	if _, err := certzcrypto.ParseKeyUsageStrict(extension.Value); err != nil {
		return false
	}
	return certificate.KeyUsage&x509.KeyUsageCRLSign != 0
}
