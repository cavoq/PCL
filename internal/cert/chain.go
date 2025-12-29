package cert

import (
	"fmt"
	"slices"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/loader"
)

func LoadCertificates(path string) ([]*Info, error) {
	results, err := loader.LoadAll(
		path,
		extensions,
		ParseCertificate,
		func(cert *x509.Certificate) []byte { return cert.Raw },
	)
	if err != nil {
		return nil, err
	}

	infos := make([]*Info, len(results))
	for i, r := range results {
		infos[i] = &Info{
			Cert:     r.Data,
			FilePath: r.FilePath,
			Hash:     r.Hash,
		}
	}
	return infos, nil
}

func BuildChain(certs []*Info) ([]*Info, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	if len(certs) == 1 {
		certs[0].Position = 0
		certs[0].Type = getCertType(certs[0].Cert, 0, 1)
		return certs, nil
	}

	subjectMap := make(map[string]*Info)
	for _, c := range certs {
		subjectMap[c.Cert.Subject.String()] = c
	}

	var longestChain []*Info

	for _, leaf := range certs {
		chain := []*Info{leaf}
		current := leaf

		for {
			if isSelfSigned(current.Cert) {
				break
			}

			issuer := subjectMap[current.Cert.Issuer.String()]
			if issuer == nil {
				break
			}

			if slices.Contains(chain, issuer) {
				break
			}

			chain = append(chain, issuer)
			current = issuer
		}

		if len(chain) > len(longestChain) {
			longestChain = chain
		}
	}

	if len(longestChain) == 0 {
		return nil, fmt.Errorf("could not build certificate chain")
	}

	for i, c := range longestChain {
		c.Position = i
		c.Type = getCertType(c.Cert, i, len(longestChain))
	}

	return longestChain, nil
}
