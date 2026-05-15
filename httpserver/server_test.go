package httpserver

import (
	"bytes"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// testServer builds a Server suitable for httptest, returning the configured cfg too
// so tests can read AuthToken etc.
func testServer(t *testing.T, opts ...func(*Config)) (*Server, Config) {
	t.Helper()

	priv, pub, err := keys.GenerateECDSA(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	cfg := Config{
		Logger:            zaptest.NewLogger(t),
		Method:            jwt.SigningMethodES256,
		PrivateKey:        priv,
		PublicKey:         pub,
		Kid:               "k1",
		DefaultIssuer:     "test-issuer",
		DefaultExpiration: time.Hour,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, cfg
}

// TestNewValidatesConfig covers required-field rejection and bad keypair rejection.
func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())

	tests := []struct {
		Mutate func(c *Config)
		Want   error
		Name   string
	}{
		{Name: "missing logger", Mutate: func(c *Config) { c.Logger = nil }, Want: pkgerr.ErrInvalidValue},
		{Name: "missing method", Mutate: func(c *Config) { c.Method = nil }, Want: pkgerr.ErrInvalidValue},
		{Name: "missing private key", Mutate: func(c *Config) { c.PrivateKey = nil }, Want: pkgerr.ErrInvalidValue},
		{Name: "missing public key", Mutate: func(c *Config) { c.PublicKey = nil }, Want: pkgerr.ErrInvalidValue},
		{Name: "mismatched pair", Mutate: func(c *Config) {
			_, otherPub, _ := keys.GenerateECDSA(elliptic.P256())
			c.PublicKey = otherPub
		}, Want: pkgerr.ErrInvalidKeyPair},
	}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			cfg := Config{
				Logger:     zap.NewNop(),
				Method:     jwt.SigningMethodES256,
				PrivateKey: priv,
				PublicKey:  pub,
			}
			test.Mutate(&cfg)
			_, err := New(cfg)
			if !errors.Is(err, test.Want) {
				t.Errorf("test %d: error mismatch\nwant: %v\ngot:  %v", testNum, test.Want, err)
			}
		})
	}
}

// TestHandlersRoundtrip covers /sign -> /verify and /refresh against an httptest server.
func TestHandlersRoundtrip(t *testing.T) {
	t.Parallel()

	srv, _ := testServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	// /healthz
	resp, body := doRequest(t, ts, http.MethodGet, "/healthz", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status: %d body=%s", resp.StatusCode, body)
	}

	// /.well-known/jwks.json
	resp, body = doRequest(t, ts, http.MethodGet, "/.well-known/jwks.json", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/jwks status: %d body=%s", resp.StatusCode, body)
	}

	// /sign
	signReq := SignRequest{Claims: jwt.MapClaims{"sub": "u1", "aud": []string{"api"}}}
	resp, body = doRequest(t, ts, http.MethodPost, "/sign", "", signReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/sign status: %d body=%s", resp.StatusCode, body)
	}
	var signResp SignResponse
	if err := json.Unmarshal([]byte(body), &signResp); err != nil {
		t.Fatalf("decode sign resp: %v body=%s", err, body)
	}
	if signResp.Token == "" {
		t.Fatal("sign returned empty token")
	}

	// /verify
	verifyReq := VerifyRequest{Token: signResp.Token}
	resp, body = doRequest(t, ts, http.MethodPost, "/verify", "", verifyReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/verify status: %d body=%s", resp.StatusCode, body)
	}
	var verifyResp VerifyResponse
	if err := json.Unmarshal([]byte(body), &verifyResp); err != nil {
		t.Fatalf("decode verify resp: %v body=%s", err, body)
	}
	if !verifyResp.Valid {
		t.Errorf("verify.Valid = false, want true; body=%s", body)
	}

	// /refresh
	resp, body = doRequest(t, ts, http.MethodPost, "/refresh", "", RefreshRequest{Token: signResp.Token})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/refresh status: %d body=%s", resp.StatusCode, body)
	}
	var refreshResp RefreshResponse
	if err := json.Unmarshal([]byte(body), &refreshResp); err != nil {
		t.Fatalf("decode refresh resp: %v body=%s", err, body)
	}
	if refreshResp.Token == "" || refreshResp.Token == signResp.Token {
		t.Errorf("refresh did not produce a new token; got %q", refreshResp.Token)
	}
}

// TestVerifyRejectsBadToken returns 200 with valid:false for unverifiable tokens.
//
// /verify is a query endpoint (the caller is asking "is this token any good?"), not
// auth-protected — 401 would imply the *caller* needs to authenticate, which is wrong.
func TestVerifyRejectsBadToken(t *testing.T) {
	t.Parallel()

	srv, _ := testServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp, body := doRequest(t, ts, http.MethodPost, "/verify", "", VerifyRequest{Token: "not-a-jwt"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200 got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"valid":false`) {
		t.Errorf("body missing valid:false; got %s", body)
	}
}

// TestAuthRequiredOnSignAndRefresh confirms bearer auth gates mutating endpoints.
func TestAuthRequiredOnSignAndRefresh(t *testing.T) {
	t.Parallel()

	const token = "shhh"
	srv, _ := testServer(t, func(c *Config) { c.AuthToken = token })
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close) // Cleanup runs after parallel subtests; defer would fire too early.

	tests := []struct {
		Path string
		Body any
	}{
		{Path: "/sign", Body: SignRequest{Claims: jwt.MapClaims{"sub": "u1"}}},
		{Path: "/refresh", Body: RefreshRequest{Token: "anything"}},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Path), func(t *testing.T) {
			t.Parallel()

			// No auth -> 401.
			resp, _ := doRequest(t, ts, http.MethodPost, test.Path, "", test.Body)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("no-auth status: %d, want 401", resp.StatusCode)
			}

			// Wrong token -> 401.
			resp, _ = doRequest(t, ts, http.MethodPost, test.Path, "wrong", test.Body)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("wrong-token status: %d, want 401", resp.StatusCode)
			}

			// Right token -> not 401 (could be 200 or 400 depending on body validity).
			resp, _ = doRequest(t, ts, http.MethodPost, test.Path, token, test.Body)
			if resp.StatusCode == http.StatusUnauthorized {
				t.Errorf("auth-token status 401 with correct token, want non-401")
			}
		})
	}
}

// doRequest issues an HTTP request to ts.URL+path and returns the response and body string.
func doRequest(t *testing.T, ts *httptest.Server, method, path, bearer string, body any) (*http.Response, string) {
	t.Helper()

	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(out)
}
