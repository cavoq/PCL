package crl

import (
	"bytes"
	"errors"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
)

type revocationPoint struct {
	point    x509ext.DistributionPoint
	index    int
	fallback bool
	names    []x509ext.GeneralName
}

func certificateRevocationPoints(
	certificate *x509.Certificate,
) ([]revocationPoint, bool, error) {
	extensions := x509ext.NewExtensionIndex(certificate.Extensions)
	value, present, err := uniqueCertificateExtension(extensions, oid.CRLDistributionPoints)
	if err != nil {
		return nil, false, err
	}
	var points []revocationPoint
	if present {
		decoded, decodeErr := x509ext.DecodeDistributionPoints(value)
		if decodeErr != nil {
			return nil, false, decodeErr
		}
		for index, point := range decoded {
			points = append(points, revocationPoint{point: point, index: index})
		}
	}

	fallbackNames, err := certificateIssuerNames(certificate, extensions)
	if err != nil {
		return nil, false, err
	}
	points = append(points, revocationPoint{
		index: -1, fallback: true, names: fallbackNames,
	})

	freshestValue, freshest, err := uniqueCertificateExtension(extensions, oid.FreshestCRL)
	if err != nil {
		return nil, false, err
	}
	if freshest {
		if _, err := x509ext.DecodeDistributionPoints(freshestValue); err != nil {
			return nil, false, err
		}
	}
	return points, freshest, nil
}

func uniqueCertificateExtension(
	extensions x509ext.ExtensionIndex,
	identifier string,
) ([]byte, bool, error) {
	match := extensions.Lookup(identifier)
	if match.Present() && !match.Unique() {
		return nil, false, errDuplicateExtension
	}
	extension, present := match.Extension()
	return extension.Value, present, nil
}

var errDuplicateExtension = errors.New("duplicate extension")

func certificateIssuerNames(
	certificate *x509.Certificate,
	extensions x509ext.ExtensionIndex,
) ([]x509ext.GeneralName, error) {
	issuer := x509ext.GeneralName{
		Tag:      4,
		RawValue: append([]byte(nil), certificate.RawIssuer...),
	}
	value, present, err := uniqueCertificateExtension(extensions, oid.IssuerAlternativeName)
	if err != nil {
		return nil, err
	}
	if !present {
		return []x509ext.GeneralName{issuer}, nil
	}
	alternativeNames, err := x509ext.DecodeGeneralNames(value)
	if err != nil {
		return nil, err
	}
	names := make([]x509ext.GeneralName, 0, 1+len(alternativeNames))
	names = append(names, issuer)
	return append(names, alternativeNames...), nil
}

func listAppliesToPoint(
	certificate *x509.Certificate,
	point revocationPoint,
	record decodedList,
) (EvidenceRejection, ReasonSet) {
	list := record.list
	idp := record.facts.IssuingDistributionPoint
	if list == nil {
		return EvidenceUnrelated, 0
	}

	switch {
	case point.fallback:
		if !namesEqual(list.RawIssuer, certificate.RawIssuer, list.Issuer.String(), certificate.Issuer.String()) {
			return EvidenceUnrelated, 0
		}
	case len(point.point.CRLIssuer) > 0:
		if !generalNamesContainDirectoryName(point.point.CRLIssuer, list.RawIssuer) {
			return EvidenceUnrelated, 0
		}
		if idp == nil || !idp.IndirectCRL {
			return EvidenceScopeMismatch, 0
		}
	case !namesEqual(list.RawIssuer, certificate.RawIssuer, list.Issuer.String(), certificate.Issuer.String()):
		return EvidenceUnrelated, 0
	}

	if idp != nil {
		certificateAssertsCA := certificate.BasicConstraintsValid && certificate.IsCA
		if idp.OnlyContainsAttributeCerts ||
			(idp.OnlyContainsUserCerts && certificateAssertsCA) ||
			(idp.OnlyContainsCACerts && !certificateAssertsCA) {
			return EvidenceScopeMismatch, 0
		}
		if idp.DistributionPoint != nil && !distributionPointNameMatches(point, record) {
			return EvidenceScopeMismatch, 0
		}
	}

	dpReasons := AllReasons
	if !point.fallback && point.point.Reasons != nil {
		if point.point.Reasons.Mask&1 != 0 {
			return EvidenceScopeMismatch, 0
		}
		dpReasons = point.point.Reasons.Mask
	}
	idpReasons := AllReasons
	if idp != nil && idp.OnlySomeReasons != nil {
		if idp.OnlySomeReasons.Mask&1 != 0 {
			return EvidenceScopeMismatch, 0
		}
		idpReasons = idp.OnlySomeReasons.Mask
	}
	return EvidenceAccepted, dpReasons & idpReasons & AllReasons
}

func distributionPointNameMatches(point revocationPoint, record decodedList) bool {
	idpName := record.facts.IssuingDistributionPoint.DistributionPoint
	if idpName == nil {
		return true
	}
	if point.fallback {
		idpNames, err := x509ext.ExpandDistributionPointName(idpName, record.list.RawIssuer)
		return err == nil && generalNamesIntersect(point.names, idpNames)
	}
	if point.point.Name == nil {
		idpNames, err := x509ext.ExpandDistributionPointName(idpName, record.list.RawIssuer)
		return err == nil && generalNamesIntersect(point.point.CRLIssuer, idpNames)
	}
	return x509ext.DistributionPointNamesIntersect(
		point.point.Name,
		idpName,
		record.list.RawIssuer,
		record.list.RawIssuer,
	)
}

func generalNamesContainDirectoryName(names []x509ext.GeneralName, rawName []byte) bool {
	for _, name := range names {
		if name.Tag == 4 && bytes.Equal(name.RawValue, rawName) {
			return true
		}
	}
	return false
}

func generalNamesIntersect(left, right []x509ext.GeneralName) bool {
	for _, first := range left {
		for _, second := range right {
			if first.Tag == second.Tag && bytes.Equal(first.RawValue, second.RawValue) {
				return true
			}
		}
	}
	return false
}

func namesEqual(firstRaw, secondRaw []byte, firstFallback, secondFallback string) bool {
	if len(firstRaw) > 0 && len(secondRaw) > 0 {
		return bytes.Equal(firstRaw, secondRaw)
	}
	return firstFallback == secondFallback
}
