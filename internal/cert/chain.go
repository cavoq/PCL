package cert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/cavoq/PCL/internal/aia"
	"github.com/cavoq/PCL/internal/source"
)

func LoadCertificates(path string) ([]*Info, error) {
	return LoadCertificatesWithSource(path, source.Info{Type: source.Local})
}

func LoadCertificatesWithSource(path string, sourceInfo source.Info) ([]*Info, error) {
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
		infoSource := sourceInfo
		if infoSource.Type == "" {
			infoSource.Type = source.Local
		}
		infoSource.Format = format
		infos = append(infos, &Info{
			Cert:     cert,
			FilePath: file,
			Hash:     hex.EncodeToString(hash[:]),
			Source:   infoSource,
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

// ClimbChain recursively fetches issuer certificates via CA Issuers URLs.
func ClimbChain(chain []*Info, timeout time.Duration, maxDepth int, w io.Writer) []*Info {
	if len(chain) == 0 || maxDepth <= 0 {
		return chain
	}

	seen := make(map[string]bool)
	for _, c := range chain {
		if c.Cert != nil && c.Cert.SerialNumber != nil {
			seen[c.Cert.SerialNumber.String()] = true
		}
	}

	result := chain
	depth := 0

	for depth < maxDepth {
		top := result[len(result)-1]
		if top.Cert == nil || IsSelfSigned(top.Cert) {
			break
		}

		if len(top.Cert.IssuingCertificateURL) == 0 {
			break
		}

		url := top.Cert.IssuingCertificateURL[0]
		issuerResult, err := aia.FetchCAIssuer(url, timeout)
		if err != nil {
			warnf(w, "Warning: failed to climb chain from %s: %v\n", url, err)
			break
		}

		issuerCert, matched := aia.SelectIssuer(top.Cert, issuerResult.Certs)
		if issuerCert == nil {
			break
		}
		if !matched && len(issuerResult.Certs) > 1 {
			warnf(w, "Warning: PKCS#7 bundle contains %d certs, no exact issuer match found, using first cert\n", len(issuerResult.Certs))
		}

		if issuerCert.SerialNumber != nil {
			serial := issuerCert.SerialNumber.String()
			if seen[serial] {
				warnf(w, "Warning: circular certificate detected at %s\n", url)
				break
			}
			seen[serial] = true
		}

		sourceInfo := issuerResult.Source
		switch issuerResult.Source.Format {
		case source.FormatPKCS7:
			sourceInfo.Type = source.Extracted
			sourceInfo.Description = "extracted from PKCS#7"
		case source.FormatPEM:
			sourceInfo.Description = "downloaded PEM"
			warnf(w, "Warning: CA Issuers URL %s returned PEM format (RFC 5280 requires DER/BER)\n", url)
		}

		result = append(result, &Info{
			Cert:     issuerCert,
			FilePath: url,
			Type:     GetCertType(issuerCert, len(result), len(result)+1),
			Position: len(result),
			Source:   sourceInfo,
			Format:   issuerResult.Source.Format,
		})

		depth++
	}

	RebuildChainMetadata(result)
	return result
}

func RebuildChainMetadata(chain []*Info) {
	for i, c := range chain {
		c.Position = i
		c.Type = GetCertType(c.Cert, i, len(chain))
	}
}

func warnf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	_, _ = fmt.Fprintf(w, format, args...)
}
