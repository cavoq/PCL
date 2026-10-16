package operator

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
)

func TestCRLOperators(t *testing.T) {
	now := time.Now()
	window := func(thisUpdate, nextUpdate time.Duration) *crl.Info {
		return &crl.Info{CRL: &x509.RevocationList{ThisUpdate: now.Add(thisUpdate), NextUpdate: now.Add(nextUpdate)}}
	}
	lists := func(infos ...*crl.Info) *EvaluationContext { return &EvaluationContext{Now: now, CRLs: infos} }

	issuer := pkix.Name{CommonName: "Test CA"}
	serial := big.NewInt(123)
	subject := &cert.Info{Cert: &x509.Certificate{SerialNumber: serial, Issuer: issuer}}
	revoking := func(name pkix.Name) *crl.Info {
		return &crl.Info{CRL: &x509.RevocationList{
			Issuer:              name,
			RevokedCertificates: []x509.RevokedCertificate{{SerialNumber: serial}},
		}}
	}

	fixtureDER, err := os.ReadFile(filepath.Join("..", "..", "internal", "crl", "testdata", "test.crl"))
	if err != nil {
		t.Fatalf("read CRL: %v", err)
	}
	fixture, err := crl.ParseCRL(fixtureDER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	// The signer hint matches the fixture's issuer but holds no key.
	unverifiable := &EvaluationContext{
		CRLs: []*crl.Info{{CRL: fixture}},
		Chain: []*cert.Info{{Cert: &x509.Certificate{
			Subject:      fixture.Issuer,
			SubjectKeyId: fixture.AuthorityKeyId,
			IsCA:         true,
			SerialNumber: big.NewInt(1),
		}}},
	}

	signedList, _, ca := signedCRLWithCA(t)
	current, notYetCurrent := window(-time.Hour, time.Hour), window(time.Hour, 2*time.Hour)
	certificate := &cert.Info{Cert: &x509.Certificate{SerialNumber: big.NewInt(123)}}

	checkEvaluations(t, nil, []evaluationCase{
		{name: "crlValid: nil context", op: CRLValid{}},
		{name: "crlValid: no CRLs", op: CRLValid{}, ctx: &EvaluationContext{}},
		{name: "crlValid: within window", op: CRLValid{}, ctx: lists(window(-time.Hour, time.Hour)), want: true},
		{name: "crlValid: before thisUpdate", op: CRLValid{}, ctx: lists(window(time.Hour, 2*time.Hour))},
		{name: "crlValid: after nextUpdate", op: CRLValid{}, ctx: lists(window(-2*time.Hour, -time.Hour))},
		{name: "crlValid: RFC 5280 CRL without nextUpdate is invalid", op: CRLValid{},
			ctx: lists(&crl.Info{CRL: &x509.RevocationList{ThisUpdate: now.Add(-time.Hour)}})},
		{name: "crlValid: skips nil CRL and validates others", op: CRLValid{},
			ctx: lists(&crl.Info{}, window(-time.Hour, time.Hour)), want: true},
		{name: "crlValid: unrelated CRL does not contaminate the current CRL", op: CRLValid{},
			ctx: &EvaluationContext{Now: now, CRLs: []*crl.Info{current, notYetCurrent}, CurrentCRL: current}, want: true},

		{name: "crlNotExpired: nil context", op: CRLNotExpired{}},
		{name: "crlNotExpired: valid", op: CRLNotExpired{}, ctx: lists(window(-time.Hour, time.Hour)), want: true},
		{name: "crlNotExpired: future nextUpdate is not expired even when not yet current", op: CRLNotExpired{},
			ctx: lists(window(time.Hour, 2*time.Hour)), want: true},
		{name: "crlNotExpired: expired", op: CRLNotExpired{},
			ctx: lists(&crl.Info{CRL: &x509.RevocationList{NextUpdate: now.Add(-time.Hour)}})},

		{name: "crlSignedBy: nil context", op: CRLSignedBy{}},
		{name: "crlSignedBy: no CRLs", op: CRLSignedBy{}, ctx: &EvaluationContext{Chain: []*cert.Info{{}}}},
		{name: "crlSignedBy: no chain", op: CRLSignedBy{}, ctx: &EvaluationContext{CRLs: []*crl.Info{{}}}},
		{name: "crlSignedBy: unverifiable signature", op: CRLSignedBy{}, ctx: unverifiable},
		{name: "crlSignedBy: issuer not in chain", op: CRLSignedBy{}, ctx: &EvaluationContext{
			CRLs:  []*crl.Info{{CRL: &x509.RevocationList{Issuer: pkix.Name{CommonName: "CRL Issuer"}}}},
			Chain: []*cert.Info{{Cert: &x509.Certificate{Subject: pkix.Name{CommonName: "Different CA"}}}},
		}},

		{name: "notRevoked: nil context", op: NotRevoked{}},
		{name: "notRevoked: nil cert", op: NotRevoked{}, ctx: &EvaluationContext{}},
		// Without an applicable CRL the operator is undecided: a NoEvidenceError.
		{name: "notRevoked: no CRLs leave the status undecided", op: NotRevoked{},
			ctx: &EvaluationContext{Now: now, Cert: subject}, wantErr: true},
		{name: "notRevoked: listed certificate", op: NotRevoked{},
			ctx: &EvaluationContext{Now: now, Cert: subject, CRLs: []*crl.Info{revoking(issuer)}}},
		{name: "notRevoked: only unrelated CRLs leave the status undecided", op: NotRevoked{},
			ctx: &EvaluationContext{Now: now, Cert: subject, CRLs: []*crl.Info{revoking(pkix.Name{CommonName: "CA B"})}}, wantErr: true},
		{name: "notRevoked: unsigned synthetic CRL cannot prove a good status", op: NotRevoked{},
			ctx: &EvaluationContext{Now: now, Cert: subject, CRLs: []*crl.Info{
				{CRL: nil},
				{CRL: &x509.RevocationList{Issuer: issuer, RevokedCertificates: []x509.RevokedCertificate{}}},
			}}},
		{name: "notRevoked: accepted CRL that does not list the certificate", op: NotRevoked{},
			ctx: &EvaluationContext{
				Now:   time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC),
				Cert:  &cert.Info{Cert: ca},
				Chain: []*cert.Info{{Cert: ca}},
				CRLs:  []*crl.Info{{CRL: signedList}},
			}, want: true},
		// No CRLs or issuer pool are supplied, so a pass can only come from
		// reusing the domain assessment selected by the evaluator.
		{name: "notRevoked: reuses a good domain assessment", op: NotRevoked{},
			ctx: &EvaluationContext{Cert: certificate, CRLAssessment: &crl.Assessment{CoveredReasons: crl.AllReasons}}, want: true},
		{name: "notRevoked: reuses a revoked domain assessment", op: NotRevoked{},
			ctx: &EvaluationContext{Cert: certificate, CRLAssessment: &crl.Assessment{Revocation: &crl.Revocation{ReasonCode: 1}}}},
	})
}
