package cert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"

	"github.com/cavoq/PCL/internal/source"
)

func LoadCertificates(path string) ([]*Info, error) {
	files, err := GetCertFiles(path)
	if err != nil {
		return nil, err
	}

	infos := make([]*Info, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		cert, format, err := parseCertificate(data)
		if err != nil {
			continue
		}

		hash := sha256.Sum256(cert.Raw)
		infos = append(infos, &Info{
			Cert:     cert,
			FilePath: file,
			Hash:     hex.EncodeToString(hash[:]),
			Source:   source.Info{Type: source.Local, Format: string(format)},
			Format:   format,
		})
	}

	if len(infos) == 0 && len(files) > 0 {
		return nil, fmt.Errorf("no valid items found in %s", path)
	}

	return infos, nil
}

func BuildChain(certs []*Info) ([]*Info, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	if len(certs) == 1 {
		certs[0].Position = 0
		certs[0].Type = GetCertType(certs[0].Cert, 0, 1)
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
			if IsSelfSigned(current.Cert) {
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
		c.Type = GetCertType(c.Cert, i, len(longestChain))
	}

	return longestChain, nil
}
