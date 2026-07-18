package oid

const (
	// Authority Information Access methods from RFC 5280.
	AccessMethodOCSP      = "1.3.6.1.5.5.7.48.1"
	AccessMethodCAIssuers = "1.3.6.1.5.5.7.48.2"

	// OCSP protocol identifiers from RFC 6960 and RFC 8954.
	OCSPBasicResponse = "1.3.6.1.5.5.7.48.1.1"
	OCSPNonce         = "1.3.6.1.5.5.7.48.1.2"
)
