package main

import "time"

// cabfWildcardVectors are subscriber certificates whose only SAN is a
// Wildcard Domain Name, for BR 3.2.2.6.
func cabfWildcardVectors(w vectorWriter) error {
	group, err := newCABFGroup(w, "cabf-wildcard", 0x7c, "Wildcard")
	if err != nil {
		return err
	}
	for index, vector := range []struct{ file, name string }{
		{"registrable-domain.pem", "*.example.com"},
		{"icann-suffix.pem", "*.com"},
		{"multi-label-icann-suffix.pem", "*.co.uk"},
		{"private-suffix.pem", "*.github.io"},
	} {
		c, err := group.template(index, "leaf", time.Time{}, []cabfPolicyInformation{cabfDVPolicy})
		if err != nil {
			return err
		}
		c.DNSNames = []string{vector.name}
		if err := group.write(vector.file, c, nil, nil); err != nil {
			return err
		}
	}
	return nil
}
