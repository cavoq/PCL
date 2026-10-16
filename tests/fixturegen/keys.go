package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
)

// Fixture keys are committed, one PEM block per key named by its Name
// header, so that regenerating the fixtures reproduces them byte for byte:
// Go generates keys from the system's randomness whatever reader it is
// given. Every signature is deterministic too (see deterministicSigner).
//
// A key name is used once per run; a name without a stored key, or whose
// stored key has another type or size, gets a new key. Keys no fixture uses
// are dropped when the file is saved. The keys sign test fixtures only.

// fixtureKeys is the key store of the running generation.
var fixtureKeys *keyStore

// keySpec describes the key a fixture needs.
type keySpec struct {
	description string
	generate    func() (crypto.Signer, error)
	matches     func(crypto.PublicKey) bool
}

func rsaKey(bits int) keySpec {
	return keySpec{
		description: fmt.Sprintf("RSA-%d", bits),
		generate:    func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, bits) },
		matches: func(public crypto.PublicKey) bool {
			key, ok := public.(*rsa.PublicKey)
			return ok && key.N.BitLen() == bits
		},
	}
}

func ecKey(curve elliptic.Curve) keySpec {
	return keySpec{
		description: curve.Params().Name,
		generate:    func() (crypto.Signer, error) { return ecdsa.GenerateKey(curve, rand.Reader) },
		matches: func(public crypto.PublicKey) bool {
			key, ok := public.(*ecdsa.PublicKey)
			return ok && key.Curve == curve
		},
	}
}

var (
	p256 = ecKey(elliptic.P256())
	p384 = ecKey(elliptic.P384())
)

// fixtureKey returns the key called name from the running generation's store.
func fixtureKey(name string, spec keySpec) (crypto.Signer, error) {
	return fixtureKeys.key(name, spec)
}

// p256Key returns the P-256 key called name.
func p256Key(name string) (crypto.Signer, error) { return fixtureKey(name, p256) }

type keyStore struct {
	path    string
	stored  map[string]crypto.Signer
	used    map[string]crypto.Signer
	created []string
}

func loadKeyStore(path string) (*keyStore, error) {
	store := &keyStore{path: path, stored: map[string]crypto.Signer{}, used: map[string]crypto.Signer{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	for rest := data; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		name := block.Headers["Name"]
		if block.Type != "PRIVATE KEY" || name == "" {
			return nil, fmt.Errorf("%s: want PRIVATE KEY blocks with a Name header, got %s %q", path, block.Type, name)
		}
		if _, duplicate := store.stored[name]; duplicate {
			return nil, fmt.Errorf("%s: key %q appears twice", path, name)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: key %q: %w", path, name, err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s: key %q cannot sign", path, name)
		}
		store.stored[name] = signer
	}
	return store, nil
}

func (store *keyStore) key(name string, spec keySpec) (crypto.Signer, error) {
	if _, used := store.used[name]; used {
		return nil, fmt.Errorf("key %q is requested twice; reuse the issued key or choose another name", name)
	}
	key, ok := store.stored[name]
	if !ok || !spec.matches(key.Public()) {
		var err error
		if key, err = spec.generate(); err != nil {
			return nil, err
		}
		store.created = append(store.created, name)
	}
	store.used[name] = key
	return deterministicSigner{key}, nil
}

// save writes the keys used in this run, sorted by name, and reports
// created and dropped keys.
func (store *keyStore) save() error {
	names := make([]string, 0, len(store.used))
	for name := range store.used {
		names = append(names, name)
	}
	slices.Sort(names)
	var out bytes.Buffer
	out.WriteString("Test-only keys of the tests/fixturegen fixtures, written by make fixtures.\nThey are public: never use them for anything else.\n\n")
	for _, name := range names {
		der, err := x509.MarshalPKCS8PrivateKey(store.used[name])
		if err != nil {
			return fmt.Errorf("key %q: %w", name, err)
		}
		if err := pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Name": name}, Bytes: der}); err != nil {
			return err
		}
	}
	var dropped []string
	for name := range store.stored {
		if _, used := store.used[name]; !used {
			dropped = append(dropped, name)
		}
	}
	slices.Sort(dropped)
	if len(store.created) > 0 {
		log.Printf("new fixture keys: %v", store.created)
	}
	if len(dropped) > 0 {
		log.Printf("dropped unused fixture keys: %v", dropped)
	}
	if current, err := os.ReadFile(store.path); err == nil && bytes.Equal(current, out.Bytes()) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(store.path, out.Bytes(), 0o600)
}

// deterministicSigner signs without randomness, whatever reader it is
// given: ECDSA with RFC 6979 nonces, RSA PKCS #1 v1.5 as always, and
// RSASSA-PSS with an all-zero salt.
type deterministicSigner struct{ crypto.Signer }

func (signer deterministicSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var random io.Reader // nil selects RFC 6979 for ECDSA
	if _, pss := opts.(*rsa.PSSOptions); pss {
		random = zeroReader{}
	}
	return signer.Signer.Sign(random, digest, opts)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
