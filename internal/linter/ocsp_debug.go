package linter

import (
	"fmt"
	"io"

	"github.com/cavoq/PCL/internal/ocsp"
	ocspzcrypto "github.com/cavoq/PCL/internal/ocsp/zcrypto"
)

// printOCSPResponseDebug prints OCSP response details for debugging.
func printOCSPResponseDebug(w io.Writer, ocspInfo *ocsp.Info, nonceOpts *ocsp.NonceOptions) {
	if ocspInfo == nil || ocspInfo.Response == nil {
		return
	}
	resp := ocspInfo.Response

	_, _ = fmt.Fprintf(w, "\n[OCSP Debug]\n")
	_, _ = fmt.Fprintf(w, "  URL: %s\n", ocspInfo.FilePath)

	// Print request info
	requestInfo := ocspInfo.RequestInfo
	_, _ = fmt.Fprintf(w, "  Request:\n")
	if requestInfo != nil && requestInfo.RequestLen > 0 {
		_, _ = fmt.Fprintf(w, "    Length: %d bytes\n", requestInfo.RequestLen)
	} else {
		_, _ = fmt.Fprintf(w, "    Length: (unknown)\n")
	}

	// Print hash algorithm used for CertID
	if requestInfo != nil && requestInfo.HashAlgorithm != "" {
		_, _ = fmt.Fprintf(w, "    CertID Hash Algorithm: %s\n", requestInfo.HashAlgorithm)
	} else {
		_, _ = fmt.Fprintf(w, "    CertID Hash Algorithm: SHA256 (default)\n")
	}

	// Print nonce request info
	if requestInfo != nil && requestInfo.NonceLen > 0 {
		_, _ = fmt.Fprintf(w, "    Nonce Length: %d bytes\n", requestInfo.NonceLen)
		_, _ = fmt.Fprintf(w, "    Nonce (hex): %s\n", requestInfo.NonceHex)
	} else if nonceOpts != nil && nonceOpts.Disabled {
		_, _ = fmt.Fprintf(w, "    Nonce: disabled\n")
	} else {
		_, _ = fmt.Fprintf(w, "    Nonce: (not requested)\n")
	}

	// Print response info
	var statusStr string
	switch resp.Status {
	case 0:
		statusStr = "Good"
	case 1:
		statusStr = "Revoked"
	case 2:
		statusStr = "Unknown"
	default:
		statusStr = fmt.Sprintf("Unknown(%d)", resp.Status)
	}
	_, _ = fmt.Fprintf(w, "  Response:\n")
	_, _ = fmt.Fprintf(w, "    Status: %s\n", statusStr)
	_, _ = fmt.Fprintf(w, "    ProducedAt: %s\n", resp.ProducedAt.Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintf(w, "    ThisUpdate: %s\n", resp.ThisUpdate.Format("2006-01-02 15:04:05"))
	if !resp.NextUpdate.IsZero() {
		_, _ = fmt.Fprintf(w, "    NextUpdate: %s\n", resp.NextUpdate.Format("2006-01-02 15:04:05"))
	} else {
		_, _ = fmt.Fprintf(w, "    NextUpdate: (not set)\n")
	}
	if !resp.RevokedAt.IsZero() {
		_, _ = fmt.Fprintf(w, "    RevokedAt: %s\n", resp.RevokedAt.Format("2006-01-02 15:04:05"))
		_, _ = fmt.Fprintf(w, "    RevocationReason: %d\n", resp.RevocationReason)
	}
	_, _ = fmt.Fprintf(w, "    SerialNumber: %s\n", resp.SerialNumber.String())
	_, _ = fmt.Fprintf(w, "    SignatureAlgorithm: %s\n", resp.SignatureAlgorithm.String())

	// Parse nonce from raw response
	nonceState := ocspzcrypto.ParseNonceFromRaw(resp.Raw)
	_, _ = fmt.Fprintf(w, "    Response Nonce:\n")
	if nonceState.Present {
		_, _ = fmt.Fprintf(w, "      Present: true\n")
		_, _ = fmt.Fprintf(w, "      Length: %d bytes\n", nonceState.Length)
		_, _ = fmt.Fprintf(w, "      Value (hex): %s\n", nonceState.HexValue)
		// Check if nonce matches request
		if requestInfo != nil && requestInfo.NonceLen > 0 && nonceState.Length == requestInfo.NonceLen {
			if nonceState.HexValue == requestInfo.NonceHex {
				_, _ = fmt.Fprintf(w, "      Match: YES (echoed correctly)\n")
			} else {
				_, _ = fmt.Fprintf(w, "      Match: NO (different value)\n")
			}
		} else if requestInfo != nil && requestInfo.NonceLen > 0 && nonceState.Length != requestInfo.NonceLen {
			_, _ = fmt.Fprintf(w, "      Match: NO (different length: requested %d, got %d)\n", requestInfo.NonceLen, nonceState.Length)
		}
	} else {
		_, _ = fmt.Fprintf(w, "      Present: false\n")
	}
	_, _ = fmt.Fprintf(w, "\n")
}
