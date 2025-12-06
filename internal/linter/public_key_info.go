package linter

import (
	"crypto/dsa" // #nosec G505 - deprecated but needed for legacy certificate validation
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"slices"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/utils"
)

func LintSubjectPublicKeyInfo(job *LintJob) {
	rule := job.Policy.Crypto.SubjectPublicKeyInfo
	cert := job.Cert

	if rule == nil || rule.AllowedAlgorithms == nil || len(rule.AllowedAlgorithms) == 0 {
		return
	}

	algName := string(utils.GetPublicKeyAlgorithm(cert))
	algRule, ok := rule.AllowedAlgorithms[algName]
	if !ok {
		job.Result.Add(
			"crypto.subject_public_key_info",
			StatusFail,
			fmt.Sprintf("public key algorithm not allowed: %s", algName),
		)
		return
	}

	LintKeyAlgorithmRule(job, algName, cert.PublicKey, algRule)
}

func LintKeyAlgorithmRule(job *LintJob, algName string, pubKey any, rule *policy.KeyAlgorithmRule) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		if rule.MinSize > 0 && key.N.BitLen() < rule.MinSize {
			job.Result.Add(
				fmt.Sprintf("crypto.subject_public_key_info.%s", algName),
				StatusFail,
				fmt.Sprintf("RSA key too small: %d bits, min required %d", key.N.BitLen(), rule.MinSize),
			)
		} else {
			job.Result.Add(
				fmt.Sprintf("crypto.subject_public_key_info.%s", algName),
				StatusPass,
				fmt.Sprintf("RSA key size acceptable: %d bits", key.N.BitLen()),
			)
		}

	case *dsa.PublicKey:
		keySize := key.P.BitLen()
		if rule.MinSize > 0 && keySize < rule.MinSize {
			job.Result.Add(
				fmt.Sprintf("crypto.subject_public_key_info.%s", algName),
				StatusFail,
				fmt.Sprintf("DSA key too small: %d bits, min required %d", keySize, rule.MinSize),
			)
		} else {
			job.Result.Add(
				fmt.Sprintf("crypto.subject_public_key_info.%s", algName),
				StatusPass,
				fmt.Sprintf("DSA key size acceptable: %d bits", keySize),
			)
		}

	case *ecdsa.PublicKey:
		if rule.MinSize > 0 && key.Params().BitSize < rule.MinSize {
			job.Result.Add(
				fmt.Sprintf("crypto.subject_public_key_info.%s", algName),
				StatusFail,
				fmt.Sprintf("EC key too small: %d bits, min required %d", key.Params().BitSize, rule.MinSize),
			)
			return
		}

		if len(rule.AllowedCurves) > 0 && !slices.Contains(rule.AllowedCurves, key.Params().Name) {
			job.Result.Add(
				fmt.Sprintf("crypto.subject_public_key_info.%s", algName),
				StatusFail,
				fmt.Sprintf("EC curve %s not allowed", key.Params().Name),
			)
		} else {
			job.Result.Add(
				fmt.Sprintf("crypto.subject_public_key_info.%s", algName),
				StatusPass,
				fmt.Sprintf("EC key curve acceptable: %s", key.Params().Name),
			)
		}

	case ed25519.PublicKey:
		job.Result.Add(
			fmt.Sprintf("crypto.subject_public_key_info.%s", algName),
			StatusPass,
			"Ed25519 key is acceptable",
		)

	default:
		job.Result.Add(
			fmt.Sprintf("crypto.subject_public_key_info.%s", algName),
			StatusFail,
			fmt.Sprintf("unknown key type: %T", pubKey),
		)
	}
}
