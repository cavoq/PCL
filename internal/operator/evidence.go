package operator

// NoEvidenceError reports that an operator could not decide because no
// applicable evidence was supplied, such as no CRL or OCSP response covering
// the certificate. Rules report it as inconclusive rather than failed:
// missing evidence leaves compliance unestablished without showing the input
// non-compliant. Evidence that is supplied but defective, such as a stale or
// unauthenticated response, still fails.
type NoEvidenceError struct {
	// Evidence names what was missing, such as "OCSP response".
	Evidence string
}

func (e NoEvidenceError) Error() string {
	return "no applicable " + e.Evidence + " was supplied for the certificate"
}
