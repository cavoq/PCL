package cert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
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

		for !IsSelfSigned(current.Cert) {

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
	return ClimbChainWithPool(chain, nil, timeout, maxDepth, w)
}

// ClimbChainWithPool is like ClimbChain but when the top certificate has no
// IssuingCertificateURL, it looks in pool for a parent that verifies the
// signature (e.g. --issuer). DN-only matches are never used.
func ClimbChainWithPool(chain, pool []*Info, timeout time.Duration, maxDepth int, w io.Writer) []*Info {
	if len(chain) == 0 || maxDepth <= 0 {
		return chain
	}

	seen := serialSeenSet(CertsFromInfos(chain))
	result := append([]*Info(nil), chain...)

	for depth := 0; depth < maxDepth; depth++ {
		top := result[len(result)-1]
		if top.Cert == nil || IsSelfSigned(top.Cert) {
			break
		}

		if len(top.Cert.IssuingCertificateURL) == 0 {
			parent := findSigningParentInPool(top.Cert, pool, seen)
			if parent == nil {
				break
			}
			if markSerialSeen(seen, parent.Cert) {
				warnf(w, "Warning: circular certificate detected at %s\n", parent.FilePath)
				break
			}
			parent.Position = len(result)
			parent.Type = GetCertType(parent.Cert, parent.Position, len(result)+1)
			result = append(result, parent)
			continue
		}

		issuerCert, sourceInfo, url, err := FetchParentViaCAIssuers(top.Cert, timeout, w)
		if err != nil {
			warnf(w, "Warning: failed to climb chain from %s: %v\n", url, err)
			break
		}
		if issuerCert == nil {
			break
		}

		if markSerialSeen(seen, issuerCert) {
			warnf(w, "Warning: circular certificate detected at %s\n", url)
			break
		}

		result = append(result, &Info{
			Cert:     issuerCert,
			FilePath: url,
			Type:     GetCertType(issuerCert, len(result), len(result)+1),
			Position: len(result),
			Source:   sourceInfo,
			Format:   sourceInfo.Format,
		})
	}

	RebuildChainMetadata(result)
	return result
}

func findSigningParentInPool(child *x509.Certificate, pool []*Info, seen map[string]bool) *Info {
	if child == nil || len(child.Raw) == 0 {
		return nil
	}
	for _, info := range pool {
		if info == nil || info.Cert == nil {
			continue
		}
		if child.CheckSignatureFrom(info.Cert) != nil {
			continue
		}
		if info.Cert.SerialNumber != nil && seen[info.Cert.SerialNumber.String()] {
			continue
		}
		return &Info{
			Cert:     info.Cert,
			FilePath: info.FilePath,
			Source:   info.Source,
			Format:   info.Format,
		}
	}
	return nil
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
