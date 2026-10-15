// Package httpread reads HTTP response bodies with a size limit, so a
// misbehaving server cannot make PCL buffer an unbounded download.
package httpread

import (
	"fmt"
	"io"
	"math"
	"net/http"
)

// Body reads the body of a 200 OK response. It fails for any other status
// and for bodies longer than maxBytes, whether announced by Content-Length
// or found while reading.
func Body(response *http.Response, maxBytes int64) ([]byte, error) {
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
