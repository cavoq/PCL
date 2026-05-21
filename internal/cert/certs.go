package cert

import "github.com/zmap/zcrypto/x509"

// CertsFromInfos extracts certificates from Info values, skipping nil entries.
func CertsFromInfos(infos []*Info) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, info := range infos {
		if info != nil && info.Cert != nil {
			certs = append(certs, info.Cert)
		}
	}
	return certs
}
