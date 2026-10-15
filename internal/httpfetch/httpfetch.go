// Package httpfetch performs PCL's HTTP requests. Every request ends at its
// context's deadline, accepts only a 200 response of bounded size, and
// identifies PCL by its user agent.
package httpfetch

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
)

// UserAgent identifies PCL in requests. The command sets it to include the
// version.
var UserAgent = "pcl"

// Client sends requests with HTTP, or with http.DefaultClient when HTTP is
// nil.
type Client struct {
	HTTP *http.Client
}

// Get retrieves url and returns a body of at most maxBytes.
func (client Client) Get(ctx context.Context, url string, maxBytes int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.do(request, maxBytes)
}

// Post sends body as contentType to url, asks for accept, and returns a
// response body of at most maxBytes.
func (client Client) Post(
	ctx context.Context,
	url, contentType, accept string,
	body []byte,
	maxBytes int64,
) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", accept)
	return client.do(request, maxBytes)
}

func (client Client) do(request *http.Request, maxBytes int64) ([]byte, error) {
	request.Header.Set("User-Agent", UserAgent)
	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	// The URLs come from certificates, CRLs and the command line; fetching
	// them is the purpose of this client.
	response, err := httpClient.Do(request) //nolint:gosec // G704: see above
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	return readBody(response, maxBytes)
}

// readBody reads the body of a 200 OK response. It fails for any other
// status and for bodies longer than maxBytes, whether announced by
// Content-Length or found while reading.
func readBody(response *http.Response, maxBytes int64) ([]byte, error) {
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", response.StatusCode)
	}
	if response.ContentLength > maxBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBytes)
	}

	readLimit := maxBytes
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, readLimit))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBytes)
	}
	return body, nil
}
