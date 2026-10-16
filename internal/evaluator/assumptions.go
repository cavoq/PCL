package evaluator

import "github.com/cavoq/PCL/internal/policy"

// AssumeProfiles records each assumption on the subjects it selects: those
// whose role is the profile's role in one of the subject's policies and,
// with a fingerprint, whose certificate or CRL has that fingerprint. OCSP
// responses are selected by role only. It returns the assumptions that
// selected no subject.
func AssumeProfiles(subjects []Subject, assumptions []policy.ProfileAssumption) []policy.ProfileAssumption {
	matched := make([]bool, len(assumptions))
	for _, subject := range subjects {
		ctx := subject.Context
		if ctx == nil {
			continue
		}
		raw := subjectDER(subject)
		for i, assumption := range assumptions {
			if assumption.Fingerprint != "" && (raw == nil || !assumption.Matches(raw)) {
				continue
			}
			for _, p := range subject.Policies {
				if policy.AssumesRole(p, assumption.Profile, ctx.Input.Kind) {
					ctx.AssumedProfiles = append(ctx.AssumedProfiles, assumption.Profile)
					matched[i] = true
					break
				}
			}
		}
	}
	var unmatched []policy.ProfileAssumption
	for i, assumption := range assumptions {
		if !matched[i] {
			unmatched = append(unmatched, assumption)
		}
	}
	return unmatched
}

// subjectDER returns the DER encoding of a certificate or CRL subject.
func subjectDER(subject Subject) []byte {
	ctx := subject.Context
	switch {
	case ctx.Cert != nil && ctx.Cert.Cert != nil:
		return ctx.Cert.Cert.Raw
	case ctx.CurrentCRL != nil && ctx.CurrentCRL.CRL != nil:
		return ctx.CurrentCRL.CRL.Raw
	}
	return nil
}
