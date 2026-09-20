package crl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	crlzcrypto "github.com/cavoq/PCL/internal/crl/zcrypto"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
)

const (
	// DefaultMaxCRLResponseBytes bounds automatic network acquisition. Local
	// files retain their existing behavior and are not subject to this limit.
	DefaultMaxCRLResponseBytes int64 = 64 << 20
	defaultFetchTimeout              = 10 * time.Second
)

var errFetchSessionRequired = errors.New("CRL fetch session is required")

// Retriever obtains one resource body. Implementations must honor ctx and
// maxBytes. FetchSession independently checks the returned size so custom
// retrievers cannot bypass the acquisition bound.
type Retriever interface {
	Retrieve(ctx context.Context, resourceURL string, maxBytes int64) ([]byte, error)
}

// FetchConfig configures one evaluation-scoped CRL acquisition session.
type FetchConfig struct {
	Timeout          time.Duration
	MaxResponseBytes int64
	Retriever        Retriever
}

type cachedFetch struct {
	info *Info
	err  error
}

// FetchSession caches both successful and failed URL retrievals and
// deduplicates byte-identical CRLs by their signed raw encoding. Public
// methods return Info snapshots; later origin discovery never mutates a value
// already held by a caller.
type FetchSession struct {
	timeout          time.Duration
	maxResponseBytes int64
	retriever        Retriever
	allowPEM         bool

	mu            sync.Mutex
	byURL         map[string]cachedFetch
	objectsByHash map[string]*Info
}

// NewFetchSession creates an isolated cache for one linter evaluation.
func NewFetchSession(cfg FetchConfig) *FetchSession {
	return newFetchSession(cfg, false)
}

// newFetchSession's allowPEM switch exists only for the legacy direct-fetch
// wrappers. Evaluation-scoped CRLDP/Freshest acquisition is always DER-only.
func newFetchSession(cfg FetchConfig, allowPEM bool) *FetchSession {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultFetchTimeout
	}
	maxResponseBytes := cfg.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = DefaultMaxCRLResponseBytes
	}
	retriever := cfg.Retriever
	if retriever == nil {
		retriever = httpRetriever{client: &http.Client{}}
	}
	return &FetchSession{
		timeout:          timeout,
		maxResponseBytes: maxResponseBytes,
		retriever:        retriever,
		allowPEM:         allowPEM,
		byURL:            make(map[string]cachedFetch),
		objectsByHash:    make(map[string]*Info),
	}
}

// Fetch retrieves one DER-encoded CRL over HTTP or HTTPS. Results and errors
// are cached by canonical URL.
func (session *FetchSession) Fetch(resourceURL string) (*Info, error) {
	if session == nil {
		return nil, errFetchSessionRequired
	}
	canonicalURL, err := canonicalCRLURL(resourceURL)
	if err != nil {
		return nil, err
	}
	return session.fetchCanonical(canonicalURL)
}

func (session *FetchSession) fetchCanonical(canonicalURL string) (*Info, error) {
	// Holding the lock through retrieval deliberately serializes a session.
	// It guarantees that concurrent callers cannot issue duplicate requests,
	// while the linter's acquisition walk remains small and deterministic.
	session.mu.Lock()
	defer session.mu.Unlock()

	if cached, ok := session.byURL[canonicalURL]; ok {
		return cloneInfo(cached.info), cached.err
	}

	ctx, cancel := context.WithTimeout(context.Background(), session.timeout)
	defer cancel()
	body, err := session.retriever.Retrieve(ctx, canonicalURL, session.maxResponseBytes)
	if err != nil {
		err = fmt.Errorf("fetching CRL from %s: %w", canonicalURL, err)
		session.byURL[canonicalURL] = cachedFetch{err: err}
		return nil, err
	}
	if int64(len(body)) > session.maxResponseBytes {
		err = fmt.Errorf(
			"CRL response from %s exceeds %d bytes",
			canonicalURL,
			session.maxResponseBytes,
		)
		session.byURL[canonicalURL] = cachedFetch{err: err}
		return nil, err
	}

	revocationList, format, err := session.parseResponse(body)
	if err != nil {
		formatDescription := "DER-encoded CRL"
		if session.allowPEM {
			formatDescription = "PEM- or DER-encoded CRL"
		}
		err = fmt.Errorf(
			"CRL response from %s is not a %s: %w",
			canonicalURL,
			formatDescription,
			err,
		)
		session.byURL[canonicalURL] = cachedFetch{err: err}
		return nil, err
	}

	hashString := crlHash(revocationList)
	if existing := session.objectsByHash[hashString]; existing != nil {
		addOrigin(existing, canonicalURL)
		session.byURL[canonicalURL] = cachedFetch{info: existing}
		return cloneInfo(existing), nil
	}

	info := &Info{
		CRL:      revocationList,
		FilePath: canonicalURL,
		Hash:     hashString,
		Source: source.Info{
			Type:   source.Downloaded,
			URL:    canonicalURL,
			Format: format,
		},
		Format:  format,
		Origins: []string{canonicalURL},
	}
	session.objectsByHash[hashString] = info
	session.byURL[canonicalURL] = cachedFetch{info: info}
	return cloneInfo(info), nil
}

func (session *FetchSession) parseResponse(body []byte) (*x509.RevocationList, source.Format, error) {
	if session.allowPEM {
		return parseCRL(body)
	}
	revocationList, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(revocationList.Raw, body) {
		return nil, "", fmt.Errorf("response contains data outside the CRL")
	}
	return revocationList, source.FormatDER, nil
}

// FetchAll retrieves each unique URL once and returns each unique CRL once,
// in first-seen order. Multiple origins remain recorded on Info.Origins.
func (session *FetchSession) FetchAll(urls []string) ([]*Info, []error) {
	if session == nil {
		return nil, []error{errFetchSessionRequired}
	}
	return session.fetchUnique(urls, make(map[string]struct{}))
}

// FetchForChain performs bounded two-stage discovery. Certificate CRLDP and
// Freshest CRL URLs are retrieved first. Freshest CRL URLs in fetched complete
// CRLs are then retrieved once; Freshest CRL on a delta CRL is never followed.
func (session *FetchSession) FetchForChain(chain []*cert.Info, warnings io.Writer) []*Info {
	if session == nil {
		writeAcquisitionErrors(warnings, []error{errFetchSessionRequired})
		return nil
	}
	attempted := make(map[string]struct{})
	initialURLs := make([]string, 0)
	for _, info := range chain {
		if info == nil || info.Cert == nil {
			continue
		}
		urls, errs := certificateDistributionPointURLs(info.Cert)
		initialURLs = append(initialURLs, urls...)
		writeAcquisitionErrors(warnings, errs)
	}

	initial, errs := session.fetchUnique(initialURLs, attempted)
	writeAcquisitionErrors(warnings, errs)

	freshestURLs := make([]string, 0)
	for _, info := range initial {
		if info == nil || info.CRL == nil {
			continue
		}
		facts, err := crlzcrypto.DecodeRevocationListStrict(info.CRL)
		if err != nil {
			writeAcquisitionErrors(warnings, []error{fmt.Errorf(
				"cannot inspect fetched CRL %s for Freshest CRL: %w",
				info.FilePath,
				err,
			)})
			continue
		}
		if facts.DeltaCRLIndicator != nil {
			continue
		}
		if facts.FreshestCRL != nil {
			freshestURLs = append(
				freshestURLs,
				x509ext.DistributionPointURIs(facts.FreshestCRL.Points)...,
			)
		}
	}

	freshest, errs := session.fetchUnique(freshestURLs, attempted)
	writeAcquisitionErrors(warnings, errs)
	return uniqueInfos(append(initial, freshest...))
}

func (session *FetchSession) fetchUnique(
	urls []string,
	attempted map[string]struct{},
) ([]*Info, []error) {
	var results []*Info
	var errs []error
	resultIndexByHash := make(map[string]int)
	for _, resourceURL := range urls {
		canonicalURL, err := canonicalCRLURL(resourceURL)
		if err != nil {
			if _, seen := attempted[resourceURL]; seen {
				continue
			}
			attempted[resourceURL] = struct{}{}
			errs = append(errs, err)
			continue
		}
		if _, seen := attempted[canonicalURL]; seen {
			continue
		}
		attempted[canonicalURL] = struct{}{}

		info, err := session.fetchCanonical(canonicalURL)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if index, duplicate := resultIndexByHash[info.Hash]; duplicate {
			// The later snapshot includes every origin known after this fetch.
			results[index] = info
			continue
		}
		resultIndexByHash[info.Hash] = len(results)
		results = append(results, info)
	}
	return results, errs
}

func certificateDistributionPointURLs(certificate *x509.Certificate) ([]string, []error) {
	extensions := x509ext.NewExtensionIndex(certificate.Extensions)
	var urls []string
	var errs []error
	for _, identifier := range []string{oid.CRLDistributionPoints, oid.FreshestCRL} {
		found, err := extensionDistributionPointURLs(extensions, identifier)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"cannot decode certificate extension %s for CRL acquisition: %w",
				identifier,
				err,
			))
			continue
		}
		urls = append(urls, found...)
	}

	// Preserve compatibility for manually constructed certificates that have
	// typed CRL URLs but no raw CRLDistributionPoints extension.
	if !extensions.Lookup(oid.CRLDistributionPoints).Present() {
		urls = append(urls, certificate.CRLDistributionPoints...)
	}
	return urls, errs
}

func extensionDistributionPointURLs(
	extensions x509ext.ExtensionIndex,
	identifier string,
) ([]string, error) {
	match := extensions.Lookup(identifier)
	if !match.Present() {
		return nil, nil
	}
	extension, unique := match.Extension()
	if !unique {
		return nil, fmt.Errorf("extension %s appears %d times", identifier, match.Count())
	}
	points, err := x509ext.DecodeDistributionPoints(extension.Value)
	if err != nil {
		return nil, err
	}
	return x509ext.DistributionPointURIs(points), nil
}

func uniqueInfos(infos []*Info) []*Info {
	byHash := make(map[string]*Info, len(infos))
	result := make([]*Info, 0, len(infos))
	for _, info := range infos {
		if info == nil {
			continue
		}
		if existing := byHash[info.Hash]; existing != nil {
			for _, origin := range info.Origins {
				addOrigin(existing, origin)
			}
			continue
		}
		snapshot := cloneInfo(info)
		byHash[info.Hash] = snapshot
		result = append(result, snapshot)
	}
	return result
}

func cloneInfo(info *Info) *Info {
	if info == nil {
		return nil
	}
	snapshot := *info
	snapshot.Origins = append([]string(nil), info.Origins...)
	return &snapshot
}

func addOrigin(info *Info, origin string) {
	for _, existing := range info.Origins {
		if existing == origin {
			return
		}
	}
	info.Origins = append(info.Origins, origin)
}

func canonicalCRLURL(resourceURL string) (string, error) {
	if resourceURL == "" {
		return "", fmt.Errorf("CRL URL is required")
	}
	parsed, err := url.Parse(resourceURL)
	if err != nil {
		return "", fmt.Errorf("invalid CRL URL %q: %w", resourceURL, err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported CRL URL scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("CRL URL %q has no host", resourceURL)
	}
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	return parsed.String(), nil
}

func writeAcquisitionErrors(w io.Writer, errs []error) {
	if w == nil {
		return
	}
	for _, err := range errs {
		_, _ = fmt.Fprintf(w, "Warning: %v\n", err)
	}
}

type httpRetriever struct {
	client *http.Client
}

func (retriever httpRetriever) Retrieve(
	ctx context.Context,
	resourceURL string,
	maxBytes int64,
) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := retriever.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned status %d", response.StatusCode)
	}
	if response.ContentLength > maxBytes {
		return nil, fmt.Errorf("CRL response exceeds %d bytes", maxBytes)
	}

	readLimit := maxBytes
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, readLimit))
	if err != nil {
		return nil, fmt.Errorf("reading CRL response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("CRL response exceeds %d bytes", maxBytes)
	}
	return body, nil
}
