package cert

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"slices"
	"time"

	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/zmap/zcrypto/dsa"
	"github.com/zmap/zcrypto/x509"
)

// LoadCertificates loads the certificates of a file, or of every certificate
// file in a directory. Directory files that cannot be read or parsed are
// reported to w and skipped; the load fails when no file yields a
// certificate.
func LoadCertificates(path string, w io.Writer) ([]*Info, error) {
	return LoadCertificatesWithSource(path, source.Info{Type: source.Local}, w)
}

func LoadCertificatesWithSource(path string, sourceInfo source.Info, w io.Writer) ([]*Info, error) {
	loaded, err := source.LoadFiles(path, extensions, ParseCertificates, w)
	if err != nil {
		return nil, err
	}

	if sourceInfo.Type == "" {
		sourceInfo.Type = source.Local
	}
	infos := make([]*Info, 0, len(loaded))
	for _, certificate := range loaded {
		infoSource := sourceInfo
		infoSource.Format = certificate.Format
		hash := sha256.Sum256(certificate.Item.Raw)
		infos = append(infos, &Info{
			Cert:     certificate.Item,
			FilePath: certificate.Path,
			Hash:     hex.EncodeToString(hash[:]),
			Source:   infoSource,
		})
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
	ResolveInheritedDSAParameters(targets, pool)

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

	return longest, nil
}

// ResolveInheritedDSAParameters applies RFC 3279 section 2.3.2 before path
// construction or validation. A DSA subjectPublicKeyInfo may omit P, Q, and G
// when they are inherited from the issuer. Parameters are resolved recursively
// because more than one adjacent certificate may omit them. The path domain
// calls this function so the compatibility behavior has one implementation.
func ResolveInheritedDSAParameters(targets, pool []*Info) {
	resolver := dsaParameterResolver{
		pool:      pool,
		resolving: make(map[*x509.Certificate]bool),
		resolved:  make(map[*x509.Certificate]bool),
	}
	for _, infos := range [][]*Info{pool, targets} {
		for _, info := range infos {
			if info != nil {
				resolver.resolve(info.Cert)
			}
		}
	}
}

type dsaParameterResolver struct {
	pool      []*Info
	resolving map[*x509.Certificate]bool
	resolved  map[*x509.Certificate]bool
}

func (resolver *dsaParameterResolver) resolve(certificate *x509.Certificate) {
	if certificate == nil || !hasInheritedDSAParameters(certificate) ||
		resolver.resolving[certificate] || resolver.resolved[certificate] {
		return
	}
	resolver.resolving[certificate] = true
	defer func() {
		delete(resolver.resolving, certificate)
		resolver.resolved[certificate] = true
	}()

	if parameters, ok := resolver.issuerParameters(certificate); ok {
		setDSAParameters(certificate, parameters)
	}
}

func (resolver *dsaParameterResolver) issuerParameters(certificate *x509.Certificate) (dsa.Parameters, bool) {
	var byKeyIdentifier, byName *x509.Certificate
	for _, info := range resolver.pool {
		if info == nil || info.Cert == nil || info.Cert == certificate ||
			!issuerNameMatches(certificate, info.Cert) {
			continue
		}
		candidate := info.Cert
		resolver.resolve(candidate)
		parameters, ok := completeDSAParameters(candidate)
		if !ok {
			continue
		}
		if SignedBy(certificate, candidate) {
			return parameters, true
		}
		if byKeyIdentifier == nil && len(certificate.AuthorityKeyId) > 0 &&
			bytes.Equal(certificate.AuthorityKeyId, candidate.SubjectKeyId) {
			byKeyIdentifier = candidate
		}
		if byName == nil {
			byName = candidate
		}
	}
	if byKeyIdentifier != nil {
		return completeDSAParameters(byKeyIdentifier)
	}
	return completeDSAParameters(byName)
}

func hasInheritedDSAParameters(certificate *x509.Certificate) bool {
	publicKey, ok := certificate.PublicKey.(*dsa.PublicKey)
	return ok && publicKey.P != nil && publicKey.Q != nil && publicKey.G != nil &&
		publicKey.P.Sign() == 0 && publicKey.Q.Sign() == 0 && publicKey.G.Sign() == 0
}

func completeDSAParameters(certificate *x509.Certificate) (dsa.Parameters, bool) {
	if certificate == nil {
		return dsa.Parameters{}, false
	}
	publicKey, ok := certificate.PublicKey.(*dsa.PublicKey)
	if !ok || publicKey.P == nil || publicKey.Q == nil || publicKey.G == nil ||
		publicKey.P.Sign() <= 0 || publicKey.Q.Sign() <= 0 || publicKey.G.Sign() <= 0 {
		return dsa.Parameters{}, false
	}
	return publicKey.Parameters, true
}

func setDSAParameters(certificate *x509.Certificate, parameters dsa.Parameters) {
	publicKey, ok := certificate.PublicKey.(*dsa.PublicKey)
	if !ok {
		return
	}
	publicKey.Parameters = dsa.Parameters{
		P: new(big.Int).Set(parameters.P),
		Q: new(big.Int).Set(parameters.Q),
		G: new(big.Int).Set(parameters.G),
	}
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
			Source:   sourceInfo,
		})
	}

	return result
}

// ExtendFromPool appends to chain the issuers found in pool by signature,
// without downloading anything, until it reaches a self-signed certificate
// or finds no issuer.
func ExtendFromPool(chain, pool []*Info) []*Info {
	if len(chain) == 0 {
		return chain
	}
	seen := NewCertificateSet(CertsFromInfos(chain)...)
	result := append([]*Info(nil), chain...)
	for {
		top := result[len(result)-1]
		if top.Cert == nil || IsSelfSigned(top.Cert) {
			return result
		}
		parent := findSigningParentInPool(top.Cert, pool, seen)
		if parent == nil || !seen.Add(parent.Cert) {
			return result
		}
		result = append(result, parent)
	}
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
		}
	}
	return nil
}

func warnf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	_, _ = fmt.Fprintf(w, format, args...)
}
