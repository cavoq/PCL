package httpread

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBody(t *testing.T) {
	response := func(status int, contentLength int64, body string) *http.Response {
		return &http.Response{
			StatusCode:    status,
			ContentLength: contentLength,
			Body:          io.NopCloser(strings.NewReader(body)),
		}
	}
	tests := []struct {
		name     string
		response *http.Response
		want     string
		wantErr  string
	}{
		{name: "within the limit", response: response(http.StatusOK, 4, "data"), want: "data"},
		{name: "exactly the limit", response: response(http.StatusOK, -1, "12345678"), want: "12345678"},
		{name: "unknown length over the limit", response: response(http.StatusOK, -1, "123456789"), wantErr: "exceeds 8 bytes"},
		{name: "announced length over the limit", response: response(http.StatusOK, 9, ""), wantErr: "exceeds 8 bytes"},
		{name: "error status", response: response(http.StatusNotFound, 0, ""), wantErr: "status 404"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := Body(tt.response, 8)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || string(body) != tt.want {
				t.Fatalf("Body() = %q, %v; want %q", body, err, tt.want)
			}
		})
	}
}
