package httpauth

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// TokenSource produces a bearer token for outbound requests.
//
// Implementations are typically file-backed (Secret-mounted token) or function-backed
// (call into an issuer like jwtsmithd's /sign on demand). Token() may block for I/O.
type TokenSource interface {
	Token() (string, error)
}

// TokenSourceFunc adapts a function to the TokenSource interface.
type TokenSourceFunc func() (string, error)

// Token calls the receiver, implementing TokenSource.
func (f TokenSourceFunc) Token() (string, error) { return f() }

// FileTokenSource reads a token from a file on every Token() call.
//
// Use for k8s Secret-mounted tokens — kubelet refreshes the file in place when the
// underlying Secret changes, so each call reads the freshest content. The file is
// re-read at most once per RefreshInterval (default 5s) to amortize disk reads.
type FileTokenSource struct {
	// Path is the filesystem path to read the token from. Required.
	Path string
	// RefreshInterval bounds how often the file is re-read. Defaults to 5s.
	RefreshInterval time.Duration

	mu       sync.RWMutex
	cached   string
	cachedAt time.Time
}

// Token returns the cached token, refreshing it from disk when stale.
func (f *FileTokenSource) Token() (string, error) {

	if f.Path == "" {
		return "", fmt.Errorf("%w: FileTokenSource.Path required", pkgerr.ErrInvalidValue)
	}

	interval := f.RefreshInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	f.mu.RLock()
	if f.cached != "" && time.Since(f.cachedAt) < interval {
		tok := f.cached
		f.mu.RUnlock()
		return tok, nil
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cached != "" && time.Since(f.cachedAt) < interval {
		return f.cached, nil
	}

	body, err := os.ReadFile(f.Path)
	if err != nil {
		return "", fmt.Errorf("%w: reading token file %s: %w", pkgerr.ErrRead, f.Path, err)
	}
	tok := strings.TrimSpace(string(body))
	if tok == "" {
		return "", fmt.Errorf("%w: token file %s is empty", pkgerr.ErrInvalidValue, f.Path)
	}
	f.cached = tok
	f.cachedAt = time.Now()
	return tok, nil
}

// StaticTokenSource returns the same token on every call.
//
// Use for tests or short-lived processes where rotation is not a concern.
type StaticTokenSource struct {
	Value string
}

// Token returns the configured static value.
func (s StaticTokenSource) Token() (string, error) {
	if s.Value == "" {
		return "", fmt.Errorf("%w: StaticTokenSource.Value empty", pkgerr.ErrInvalidValue)
	}
	return s.Value, nil
}

// CachedTokenSource wraps another TokenSource and caches the most recent value for
// the duration returned by TTL. Use when the wrapped source is expensive (e.g. it
// calls an issuer over the network).
type CachedTokenSource struct {
	// Source is the wrapped token source. Required.
	Source TokenSource
	// TTL bounds how long a cached token is reused. Required.
	TTL time.Duration

	value    atomic.Value // string
	expireAt atomic.Int64 // unix nanos
	mu       sync.Mutex
}

// Token returns the cached value when fresh; otherwise refreshes via Source.
func (c *CachedTokenSource) Token() (string, error) {

	if c.Source == nil {
		return "", fmt.Errorf("%w: CachedTokenSource.Source required", pkgerr.ErrInvalidValue)
	}
	if c.TTL <= 0 {
		return "", fmt.Errorf("%w: CachedTokenSource.TTL required", pkgerr.ErrInvalidValue)
	}

	if v, _ := c.value.Load().(string); v != "" && time.Now().UnixNano() < c.expireAt.Load() {
		return v, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if v, _ := c.value.Load().(string); v != "" && time.Now().UnixNano() < c.expireAt.Load() {
		return v, nil
	}

	tok, err := c.Source.Token()
	if err != nil {
		return "", err
	}
	c.value.Store(tok)
	c.expireAt.Store(time.Now().Add(c.TTL).UnixNano())
	return tok, nil
}

// roundTripper is an http.RoundTripper that adds Authorization: Bearer to every request.
type roundTripper struct {
	source TokenSource
	base   http.RoundTripper
}

// NewRoundTripper wraps base with bearer-token injection from src.
//
// When base is nil, http.DefaultTransport is used. The wrapped transport is safe for
// concurrent use as long as src.Token() is safe for concurrent use.
//
// Panics on construction if src is nil — required dependency.
func NewRoundTripper(src TokenSource, base http.RoundTripper) http.RoundTripper {

	if src == nil {
		panic("httpauth.NewRoundTripper: TokenSource required")
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &roundTripper{source: src, base: base}
}

// RoundTrip implements http.RoundTripper.
func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	tok, err := r.source.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: fetching outbound token: %w", pkgerr.ErrRead, err)
	}

	cloned := req.Clone(req.Context())
	cloned.Header.Set("Authorization", "Bearer "+tok)
	return r.base.RoundTrip(cloned)
}

// NewClient is a convenience that returns an *http.Client with NewRoundTripper installed.
func NewClient(src TokenSource, base http.RoundTripper) *http.Client {
	return &http.Client{Transport: NewRoundTripper(src, base)}
}
