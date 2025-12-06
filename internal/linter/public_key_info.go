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
	if job.Policy.Crypto == nil {
		return
	}

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

func keyInfoField(algName string) string {
	return fmt.Sprintf("crypto.subject_public_key_info.%s", algName)
}

func (job *LintJob) addKeySizeCheck(algName, keyType string, actualSize, minRequired int) {
	field := keyInfoField(algName)
	if minRequired > 0 && actualSize < minRequired {
		job.Result.Add(field, StatusFail,
			fmt.Sprintf("%s key too small: %d bits, min required %d", keyType, actualSize, minRequired))
	} else {
		job.Result.Add(field, StatusPass,
			fmt.Sprintf("%s key size acceptable: %d bits", keyType, actualSize))
	}
}

func LintKeyAlgorithmRule(job *LintJob, algName string, pubKey any, rule *policy.KeyAlgorithmRule) {
	field := keyInfoField(algName)

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		job.addKeySizeCheck(algName, "RSA", key.N.BitLen(), rule.MinSize)

	case *dsa.PublicKey:
		job.addKeySizeCheck(algName, "DSA", key.P.BitLen(), rule.MinSize)

	case *ecdsa.PublicKey:
		if rule.MinSize > 0 && key.Params().BitSize < rule.MinSize {
			job.Result.Add(field, StatusFail,
				fmt.Sprintf("EC key too small: %d bits, min required %d", key.Params().BitSize, rule.MinSize))
			return
		}
		curveAllowed := len(rule.AllowedCurves) == 0 || slices.Contains(rule.AllowedCurves, key.Params().Name)
		job.Result.AddCheck(field, curveAllowed,
			fmt.Sprintf("EC key curve acceptable: %s", key.Params().Name),
			fmt.Sprintf("EC curve %s not allowed", key.Params().Name))

	case ed25519.PublicKey:
		job.Result.Add(field, StatusPass, "Ed25519 key is acceptable")

	default:
		job.Result.Add(field, StatusFail, fmt.Sprintf("unknown key type: %T", pubKey))
	}
}
