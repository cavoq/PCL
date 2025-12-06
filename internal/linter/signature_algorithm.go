package linter

import (
	"crypto/x509"
	"fmt"
)

func LintSignatureAlgorithm(job *LintJob) {
	cert := job.Cert
	rule := job.Policy.Crypto

	if rule == nil || rule.SignatureAlgorithm == nil || len(rule.SignatureAlgorithm.AllowedAlgorithms) == 0 {
		return
	}

	actual := cert.SignatureAlgorithm.String()
	allowed := rule.SignatureAlgorithm.AllowedAlgorithms

	status := StatusFail
	message := ""

	if isSignatureAlgorithmAllowed(actual, allowed) {
		status = StatusPass
		message = fmt.Sprintf("signature algorithm allowed - %s", actual)
	} else {
		message = fmt.Sprintf("signature algorithm not allowed - %s", actual)
	}

	job.Result.Add("crypto.signature_algorithm", status, message)
}

func LintSignatureValidity(job *LintJob) {
	cert := job.Cert
	chain := job.Chain

	var issuer *x509.Certificate
	for _, c := range chain {
		if c.Subject.String() == cert.Issuer.String() {
			issuer = c
			break
		}
	}

	if issuer == nil {
		if cert.Subject.String() == cert.Issuer.String() {
			issuer = cert
		} else {
			job.Result.Add(
				"crypto.signature_valid",
				StatusFail,
				"issuer certificate not found in chain",
			)
			return
		}
	}

	err := issuer.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		job.Result.Add(
			"crypto.signature_valid",
			StatusFail,
			fmt.Sprintf("certificate signature is invalid: %v", err),
		)
	} else {
		job.Result.Add(
			"crypto.signature_valid",
			StatusPass,
			"certificate signature is cryptographically valid",
		)
	}
}

func isSignatureAlgorithmAllowed(actual string, allowed []string) bool {
	for _, algo := range allowed {
		if algo == "*" || algo == actual {
			return true
		}
	}
	return false
}
