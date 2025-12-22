package cert

import (
	"crypto/sha256"
	"fmt"
	"log"
	"slices"
)

func GetCertificates(path string) ([]*Info, error) {
	certFiles, err := GetCertFiles(path)
	if err != nil {
		return nil, err
	}

	certs := make([]*Info, 0, len(certFiles))
	for _, f := range certFiles {
		c, err := GetCertificate(f)
		if err != nil {
			log.Printf("warning: skipping %s: %v", f, err)
			continue
		}
		hash := sha256.Sum256(c.Raw)
		certs = append(certs, &Info{
			Cert:     c,
			FilePath: f,
			Hash:     fmt.Sprintf("%x", hash),
		})
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in %s", path)
	}

	return BuildChain(certs)
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
