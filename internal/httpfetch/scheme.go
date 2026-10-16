package httpfetch

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// HTTPURLs returns the HTTP(S) URLs among urls, the only ones PCL
// retrieves, as the CA/B Forum Baseline Requirements require for
// publicly-trusted certificates. When urls is non-empty and none is
// HTTP(S), it returns one error naming them, with kind describing where
// they came from, such as "CA Issuers".
func HTTPURLs(urls []string, kind string) ([]string, error) {
	var supported []string
	var schemes []string
	for _, rawURL := range urls {
		scheme := urlScheme(rawURL)
		if scheme == "http" || scheme == "https" {
			supported = append(supported, rawURL)
			continue
		}
		if scheme != "" && !slices.Contains(schemes, scheme) {
			schemes = append(schemes, scheme)
		}
	}
	if len(supported) > 0 || len(urls) == 0 {
		return supported, nil
	}

	labels := make([]string, len(schemes))
	for index, scheme := range schemes {
		labels[index] = scheme + "://"
	}
	if len(labels) == 0 {
		labels = []string{"non-HTTP(S)"}
	}
	return nil, fmt.Errorf(
		"only %s %s URLs (%s); %s retrieval is not supported",
		strings.Join(labels, ", "),
		kind,
		strings.Join(urls, ", "),
		unsupportedProtocols(schemes),
	)
}

func urlScheme(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Scheme)
}

func unsupportedProtocols(schemes []string) string {
	if len(schemes) == 0 {
		return "non-HTTP(S)"
	}
	protocols := make([]string, len(schemes))
	for index, scheme := range schemes {
		protocols[index] = strings.ToUpper(scheme)
	}
	return strings.Join(protocols, " and ")
}
