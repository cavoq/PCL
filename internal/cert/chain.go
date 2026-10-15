package cert

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/x509asn1"
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
	var firstErr error
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			firstErr = cmp.Or(firstErr, fmt.Errorf("%s: %w", file, err))
			continue
		}

		certs, format, err := ParseCertificates(data)
		if err != nil {
			firstErr = cmp.Or(firstErr, fmt.Errorf("%s: %w", file, err))
			continue
		}

		infoSource := sourceInfo
		if infoSource.Type == "" {
			infoSource.Type = source.Local
		}
		infoSource.Format = format
		for _, cert := range certs {
			hash := sha256.Sum256(cert.Raw)
			infos = append(infos, &Info{
				Cert:     cert,
				FilePath: file,
				Hash:     hex.EncodeToString(hash[:]),
				Source:   infoSource,
				Format:   format,
			})
		}
	}

	if len(infos) == 0 && len(files) > 0 {
		return nil, fmt.Errorf("no valid items found in %s: %w", path, firstErr)
	}

	return infos, nil
}

// BuildChain builds the longest certification path that starts at any of
// certs and continues with issuers among certs.
func BuildChain(certs []*Info) ([]*Info, error) {
	return BuildChainFor(certs, certs)
}

// BuildChainFor builds the longest certification path that starts at one of
// targets and continues with issuers from pool, ending at a self-signed
// certificate or the last certificate whose issuer is not in pool. Chains
// never start at a certificate that is only in pool, so a target whose issuer
// is missing is still evaluated, as a chain of its own.
//
// Among certificates whose subject matches a certificate's issuer, the one
// whose key verifies the signature is preferred, then one whose subject key
// identifier matches the authority key identifier, then the first; so key
// rollover and separate CRL-signing certificates with equal names do not
// replace each other.
func BuildChainFor(targets, pool []*Info) ([]*Info, error) {
	var longest []*Info
	for _, target := range targets {
		if target == nil || target.Cert == nil {
			continue
		}
		chain := []*Info{target}
		for current := target; !IsSelfSigned(current.Cert) && len(chain) <= len(pool); {
			issuer := selectIssuer(current, pool, chain)
			if issuer == nil {
				break
			}
			chain = append(chain, issuer)
			current = issuer
		}
		if len(chain) > len(longest) {
			longest = chain
		}
	}
	if len(longest) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	RebuildChainMetadata(longest)
	return longest, nil
}

func selectIssuer(current *Info, pool, chain []*Info) *Info {
	var byKeyIdentifier, byName *Info
	for _, candidate := range pool {
		if candidate == nil || candidate.Cert == nil || slices.Contains(chain, candidate) ||
			!issuerNameMatches(current.Cert, candidate.Cert) {
			continue
		}
		if SignedBy(current.Cert, candidate.Cert) {
			return candidate
		}
		if byKeyIdentifier == nil && len(current.Cert.AuthorityKeyId) > 0 &&
			bytes.Equal(current.Cert.AuthorityKeyId, candidate.Cert.SubjectKeyId) {
			byKeyIdentifier = candidate
		}
		if byName == nil {
			byName = candidate
		}
	}
	if byKeyIdentifier != nil {
		return byKeyIdentifier
	}
	return byName
}

func issuerNameMatches(child, issuer *x509.Certificate) bool {
	return x509asn1.NamesMatchOrText(child.RawIssuer, issuer.RawSubject, child.Issuer.String(), issuer.Subject.String())
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

	seen := NewCertificateSet(CertsFromInfos(chain)...)
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
			if !seen.Add(parent.Cert) {
				warnf(w, "Warning: circular certificate detected at %s\n", parent.FilePath)
				break
			}
			parent.Position = len(result)
			parent.Type = GetCertType(parent.Cert)
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

		if !seen.Add(issuerCert) {
			warnf(w, "Warning: circular certificate detected at %s\n", url)
			break
		}

		result = append(result, &Info{
			Cert:     issuerCert,
			FilePath: url,
			Type:     GetCertType(issuerCert),
			Position: len(result),
			Source:   sourceInfo,
			Format:   sourceInfo.Format,
		})
	}

	RebuildChainMetadata(result)
	return result
}

func findSigningParentInPool(child *x509.Certificate, pool []*Info, seen *CertificateSet) *Info {
	if child == nil || len(child.Raw) == 0 {
		return nil
	}
	for _, info := range pool {
		if info == nil || info.Cert == nil {
			continue
		}
		if CheckSignatureFrom(child, info.Cert) != nil {
			continue
		}
		if seen.Contains(info.Cert) {
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
		c.Type = GetCertType(c.Cert)
	}
}

func warnf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	_, _ = fmt.Fprintf(w, format, args...)
}
