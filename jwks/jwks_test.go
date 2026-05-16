package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dcadolph/jwtmint/keys"
	"github.com/dcadolph/jwtmint/pkgerr"
)

// TestJWKRoundtripPerAlgorithm encodes then decodes a public key for each supported kty.
func TestJWKRoundtripPerAlgorithm(t *testing.T) {
	t.Parallel()

	_, ecPub, _ := keys.GenerateECDSA(elliptic.P256())
	_, rsaPub, _ := keys.GenerateRSA(2048)
	_, edPub, _ := keys.GenerateEd25519()

	tests := []struct {
		Pub  any
		Name string
		Kid  string
	}{
		{Name: "ec p256", Pub: ecPub, Kid: "ec1"},
		{Name: "rsa 2048", Pub: rsaPub, Kid: "rsa1"},
		{Name: "ed25519", Pub: edPub, Kid: "ed1"},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			j, err := JWKFromPublicKey(test.Pub, test.Kid)
			if err != nil {
				t.Fatalf("JWKFromPublicKey: %v", err)
			}
			if j.Kid != test.Kid {
				t.Errorf("kid: want %q got %q", test.Kid, j.Kid)
			}
			got, err := PublicKeyFromJWK(j)
			if err != nil {
				t.Fatalf("PublicKeyFromJWK: %v", err)
			}
			if !samePublicKey(test.Pub, got) {
				t.Errorf("roundtrip mismatch for %s", test.Name)
			}
		})
	}
}

// samePublicKey compares two public keys by value-typed equality.
func samePublicKey(a, b any) bool {
	switch x := a.(type) {
	case *rsa.PublicKey:
		y, ok := b.(*rsa.PublicKey)
		return ok && x.N.Cmp(y.N) == 0 && x.E == y.E
	case *ecdsa.PublicKey:
		y, ok := b.(*ecdsa.PublicKey)
		return ok && x.X.Cmp(y.X) == 0 && x.Y.Cmp(y.Y) == 0 && x.Curve == y.Curve
	case ed25519.PublicKey:
		y, ok := b.(ed25519.PublicKey)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if x[i] != y[i] {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// TestKeySetLookup covers add, lookup, replace, remove, and duplicate-add.
func TestKeySetLookup(t *testing.T) {
	t.Parallel()

	_, pub, _ := keys.GenerateECDSA(elliptic.P256())
	j, err := JWKFromPublicKey(pub, "k1")
	if err != nil {
		t.Fatalf("JWKFromPublicKey: %v", err)
	}

	ks := NewKeySet()
	if err := ks.Add(j); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := ks.Add(j); !errors.Is(err, pkgerr.ErrInvalidValue) {
		t.Errorf("duplicate add: want ErrInvalidValue, got %v", err)
	}
	if _, err := ks.Lookup("k1"); err != nil {
		t.Errorf("Lookup k1: %v", err)
	}
	if _, err := ks.Lookup("missing"); !errors.Is(err, pkgerr.ErrNotFound) {
		t.Errorf("Lookup missing: want ErrNotFound, got %v", err)
	}
	ks.Replace(j)
	ks.Remove("k1")
	if ks.Len() != 0 {
		t.Errorf("after Remove: len = %d, want 0", ks.Len())
	}
}

// TestRemoteFetchesAndCaches verifies a single fetch on first call and cache hit on the next.
func TestRemoteFetchesAndCaches(t *testing.T) {
	t.Parallel()

	_, pub, _ := keys.GenerateECDSA(elliptic.P256())
	j, _ := JWKFromPublicKey(pub, "k1")

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{j}})
	}))
	defer srv.Close()

	r, err := NewRemote(srv.URL, WithTTL(time.Hour))
	if err != nil {
		t.Fatalf("NewRemote: %v", err)
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		ks, err := r.KeySet(ctx)
		if err != nil {
			t.Fatalf("KeySet: %v", err)
		}
		if _, err := ks.PublicKey("k1"); err != nil {
			t.Errorf("PublicKey k1: %v", err)
		}
	}
	if hits != 1 {
		t.Errorf("expected 1 fetch, got %d", hits)
	}

	if _, err := r.Refresh(ctx); err != nil {
		t.Errorf("Refresh: %v", err)
	}
	if hits != 2 {
		t.Errorf("expected 2 fetches after Refresh, got %d", hits)
	}
}

// TestRemoteHTTPError surfaces non-2xx responses as errors.
func TestRemoteHTTPError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r, _ := NewRemote(srv.URL)
	_, err := r.KeySet(context.Background())
	if !errors.Is(err, pkgerr.ErrRead) {
		t.Errorf("want ErrRead, got %v", err)
	}
}

// TestRemoteRespectsCacheControl confirms a server max-age smaller than the configured
// TTL shortens the per-fetch cache lifetime.
func TestRemoteRespectsCacheControl(t *testing.T) {
	t.Parallel()

	_, pub, _ := keys.GenerateECDSA(elliptic.P256())
	j, _ := JWKFromPublicKey(pub, "k1")

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=1")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{j}})
	}))
	defer srv.Close()

	r, _ := NewRemote(srv.URL, WithTTL(time.Hour))

	ctx := context.Background()
	if _, err := r.KeySet(ctx); err != nil {
		t.Fatalf("KeySet: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := r.KeySet(ctx); err != nil {
		t.Fatalf("KeySet (after server-shortened TTL): %v", err)
	}
	if hits != 2 {
		t.Errorf("expected 2 fetches after server max-age elapsed, got %d", hits)
	}
}

// TestParseCacheControlMaxAge covers the directive parser across realistic header shapes.
func TestParseCacheControlMaxAge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Header string
		Want   time.Duration
		WantOK bool
	}{
		{Header: "max-age=60", Want: 60 * time.Second, WantOK: true},
		{Header: "public, max-age=300", Want: 300 * time.Second, WantOK: true},
		{Header: "Max-Age=42", Want: 42 * time.Second, WantOK: true},
		{Header: "max-age=0", Want: 0, WantOK: true},
		{Header: "no-store", Want: 0, WantOK: false},
		{Header: "no-cache, max-age=60", Want: 0, WantOK: false},
		{Header: "max-age=-1", Want: 0, WantOK: false},
		{Header: "max-age=foo", Want: 0, WantOK: false},
		{Header: "", Want: 0, WantOK: false},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %q", testNum, test.Header), func(t *testing.T) {
			t.Parallel()
			got, ok := parseCacheControlMaxAge(test.Header)
			if ok != test.WantOK {
				t.Errorf("ok: want %v got %v", test.WantOK, ok)
			}
			if got != test.Want {
				t.Errorf("dur: want %v got %v", test.Want, got)
			}
		})
	}
}
