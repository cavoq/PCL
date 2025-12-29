package cert

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func DownloadCertificates(urls []string, timeout time.Duration, saveDir string) (string, func(), error) {
	if len(urls) == 0 {
		return "", nil, fmt.Errorf("no certificate URLs provided")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	dir := saveDir
	var cleanup func()
	if dir == "" {
		tmp, err := os.MkdirTemp("", "pcl-certs-*")
		if err != nil {
			return "", nil, fmt.Errorf("creating temp dir: %w", err)
		}
		dir = tmp
		cleanup = func() {
			_ = os.RemoveAll(tmp)
		}
	} else {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", nil, fmt.Errorf("creating save dir: %w", err)
		}
	}

	usedNames := make(map[string]bool)

	for i, rawURL := range urls {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return "", cleanup, fmt.Errorf("invalid url %q: %w", rawURL, err)
		}
		if parsed.Scheme != "https" {
			return "", cleanup, fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
		}

		host, port := splitHostPort(parsed.Host)
		filename := fmt.Sprintf("%s-%d.pem", sanitizeFilename(host), i+1)
		filename = uniqueFilename(filename, usedNames)
		usedNames[filename] = true

		certs, err := tlsChainFetcher(host, port, timeout)
		if err != nil {
			return "", cleanup, err
		}

		for j, cert := range certs {
			name := filename
			if len(certs) > 1 {
				base := strings.TrimSuffix(filename, filepath.Ext(filename))
				name = fmt.Sprintf("%s-%d.pem", base, j+1)
				name = uniqueFilename(name, usedNames)
			}
			usedNames[name] = true
			destPath := filepath.Join(dir, name)
			if err := writePEMCert(destPath, cert); err != nil {
				return "", cleanup, err
			}
		}
	}

	return dir, cleanup, nil
}

var tlsChainFetcher = fetchTLSChain

func uniqueFilename(name string, used map[string]bool) string {
	if !used[name] {
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d%s", base, i, ext)
		if !used[candidate] {
			return candidate
		}
	}
}

func splitHostPort(hostport string) (string, string) {
	if hostport == "" {
		return "", "443"
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, "443"
	}
	if port == "" {
		port = "443"
	}
	return host, port
}

func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, ":", "-")
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, "\\", "-")
	if name == "" {
		return "cert"
	}
	return name
}

func writePEMCert(path string, cert *tls.Certificate) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return fmt.Errorf("no certificate data to write")
	}
	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file %s: %w", path, err)
	}
	defer func() {
		_ = out.Close()
	}()
	for _, der := range cert.Certificate {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
		if err := pem.Encode(out, block); err != nil {
			return fmt.Errorf("writing file %s: %w", path, err)
		}
	}
	return nil
}

func fetchTLSChain(host, port string, timeout time.Duration) ([]*tls.Certificate, error) {
	if host == "" {
		return nil, fmt.Errorf("missing host in URL")
	}
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates from %s", addr)
	}

	certs := make([]*tls.Certificate, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		certs = append(certs, &tls.Certificate{Certificate: [][]byte{cert.Raw}})
	}
	return certs, nil
}
