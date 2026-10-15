package httpfetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientRequests(t *testing.T) {
	var got struct {
		method, contentType, accept, userAgent, body string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.method, got.body = r.Method, string(body)
		got.contentType, got.accept = r.Header.Get("Content-Type"), r.Header.Get("Accept")
		got.userAgent = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	oldAgent := UserAgent
	UserAgent = "pcl/test"
	t.Cleanup(func() { UserAgent = oldAgent })
	client := Client{HTTP: server.Client()}

	body, err := client.Get(context.Background(), server.URL, 64)
	if err != nil || string(body) != "response" || got.method != http.MethodGet || got.userAgent != "pcl/test" {
		t.Fatalf("Get = %q, %v; request %+v", body, err, got)
	}

	body, err = client.Post(context.Background(), server.URL, "application/ocsp-request", "application/ocsp-response", []byte("request"), 64)
	if err != nil || string(body) != "response" {
		t.Fatalf("Post = %q, %v", body, err)
	}
	if got.method != http.MethodPost || got.body != "request" ||
		got.contentType != "application/ocsp-request" || got.accept != "application/ocsp-response" ||
		got.userAgent != "pcl/test" {
		t.Fatalf("Post request = %+v", got)
	}
}

func TestClientHonorsTheContextDeadline(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := (Client{}).Get(ctx, server.URL, 64); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get past the deadline = %v, want context.DeadlineExceeded", err)
	}
}
