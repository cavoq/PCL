package crl

import "github.com/zmap/zcrypto/x509"

// AssessCertificate is the compatibility wrapper for a one-shot assessment.
// Callers evaluating more than one certificate against the same inputs should
// build a Catalog and reuse it.
func AssessCertificate(
	certificate *x509.Certificate,
	lists []*x509.RevocationList,
	ctx RevocationContext,
) Assessment {
	if certificate == nil || certificate.SerialNumber == nil || ctx.Now.IsZero() {
		return Assessment{}
	}
	points, freshest, err := certificateRevocationPoints(certificate)
	return NewCatalog(lists, ctx).assessCertificate(
		certificate,
		points,
		freshest,
		err,
	)
}

type assessmentRun struct {
	catalog         *Catalog
	target          *x509.Certificate
	signerDecisions map[*decodedList]signerDecision
	entryMatches    map[*decodedList]entryMatch
	deltaDecisions  map[*decodedList]deltaDecision
	targetEntryKey  targetEntryKey
}

// AssessCertificate applies the prepared catalog to one target. All mutable
// caches are confined to this call so target-dependent authorization cannot
// leak between certificates.
func (catalog *Catalog) AssessCertificate(
	certificate *x509.Certificate,
) Assessment {
	if catalog == nil || certificate == nil || certificate.SerialNumber == nil ||
		catalog.now.IsZero() {
		return Assessment{}
	}

	points, freshest, err := certificateRevocationPoints(certificate)
	return catalog.assessCertificate(certificate, points, freshest, err)
}

func (catalog *Catalog) assessCertificate(
	certificate *x509.Certificate,
	points []revocationPoint,
	freshest bool,
	pointError error,
) Assessment {
	var assessment Assessment
	if pointError != nil {
		for index := range catalog.records {
			record := &catalog.records[index]
			assessment.Evidence = append(assessment.Evidence, Evidence{
				CRL: record.list, DistributionPoint: -1,
				Rejection: EvidenceCertificateDistributionPoint,
			})
		}
		return assessment
	}
	for _, record := range catalog.malformed {
		assessment.Evidence = append(assessment.Evidence, Evidence{
			CRL: record.list, DistributionPoint: -1,
			Rejection: EvidenceMalformed,
		})
	}

	run := assessmentRun{
		catalog:         catalog,
		target:          certificate,
		signerDecisions: make(map[*decodedList]signerDecision),
		entryMatches:    make(map[*decodedList]entryMatch),
		deltaDecisions:  make(map[*decodedList]deltaDecision),
		targetEntryKey:  newTargetEntryKey(certificate),
	}
	complete := catalog.completeCandidates(run.targetEntryKey)
	seenAdvertised := make(map[listFingerprint]struct{})
	for _, point := range points {
		if point.fallback && assessment.Status() != RevocationUnknown {
			break
		}
		for _, candidate := range complete {
			if assessment.Status() != RevocationUnknown {
				break
			}
			base := candidate.record
			if point.fallback {
				if _, advertised := seenAdvertised[base.fingerprint]; advertised {
					continue
				}
			}
			evidence, revocation := run.assessCompleteCRL(
				point,
				candidate,
				freshest,
				assessment.CoveredReasons,
			)
			assessment.Evidence = append(assessment.Evidence, evidence)
			if !point.fallback && evidence.Applicable {
				seenAdvertised[base.fingerprint] = struct{}{}
			}
			if !evidence.Accepted {
				continue
			}
			assessment.CoveredReasons |= evidence.Reasons
			if revocation != nil && assessment.Revocation == nil {
				assessment.Revocation = revocation
			}
		}
	}

	return assessment
}

func (run *assessmentRun) assessCompleteCRL(
	point revocationPoint,
	candidate completeCandidate,
	certificateFreshest bool,
	covered ReasonSet,
) (Evidence, *Revocation) {
	base := candidate.record
	evidence := Evidence{
		CRL: base.list, DistributionPoint: point.index, Fallback: point.fallback,
	}
	rejection, reasons := listAppliesToPoint(run.target, point, *base)
	if rejection != EvidenceAccepted {
		evidence.Rejection = rejection
		return evidence, nil
	}
	evidence.Applicable = true
	if len(base.facts.UnsupportedCriticalExtensionOIDs) > 0 {
		evidence.Rejection = EvidenceUnsupportedCritical
		return evidence, nil
	}
	evidence.Reasons = reasons &^ covered
	if evidence.Reasons == 0 {
		evidence.Rejection = EvidenceNoNewReasons
		return evidence, nil
	}

	signer, rejection := run.authenticatedSigner(base)
	if signer == nil {
		evidence.Rejection = rejection
		return evidence, nil
	}
	evidence.Signer = signer.certificate

	var delta *decodedList
	if run.catalog.useDeltas &&
		(certificateFreshest || base.facts.FreshestCRL != nil) {
		delta = run.selectCompatibleDelta(base, signer)
	}
	if delta == nil {
		if !base.current {
			evidence.Rejection = EvidenceNotCurrent
			return evidence, nil
		}
	} else {
		evidence.Delta = delta.list
		// A delta can update a stale complete CRL, but never a complete CRL
		// that had not yet been issued or has an invalid declared window.
		if !base.baseUsable {
			evidence.Rejection = EvidenceNotCurrent
			return evidence, nil
		}
	}

	if base.entries.invalidFor(false) ||
		(delta != nil && delta.entries.invalidFor(true)) {
		evidence.Rejection = EvidenceInvalidEntry
		return evidence, nil
	}

	if delta != nil {
		match := run.entryMatch(delta)
		if match.invalid {
			evidence.Rejection = EvidenceInvalidEntry
			return evidence, nil
		}
		if match.found {
			evidence.Accepted = true
			if match.removesFromCRL() { // removeFromCRL overrides the base.
				return evidence, nil
			}
			return evidence, match.revocation(base.list, delta.list)
		}
	}

	match := candidate.match
	if match.invalid {
		evidence.Rejection = EvidenceInvalidEntry
		return evidence, nil
	}
	evidence.Accepted = true
	if match.found {
		return evidence, match.revocation(base.list, nil)
	}
	return evidence, nil
}

func (run *assessmentRun) entryMatch(record *decodedList) entryMatch {
	if match, found := run.entryMatches[record]; found {
		return match
	}
	match := record.entries.findTarget(run.targetEntryKey)
	run.entryMatches[record] = match
	return match
}
