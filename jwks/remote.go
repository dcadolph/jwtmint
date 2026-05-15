package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// DefaultRemoteTTL is the cache lifetime applied when none is provided.
const DefaultRemoteTTL = 10 * time.Minute

// Remote fetches a JWKS from a URL, caching the result for a configurable TTL.
//
// Lookup returns the cached set when fresh; on miss or expiry it fetches and atomically
// swaps. Concurrent callers during a refresh share a single in-flight request via the
// embedded singleflight-like guard, avoiding stampedes.
type Remote struct {
	url    string
	client *http.Client
	ttl    time.Duration

	mu        sync.RWMutex
	cached    *KeySet
	expiresAt time.Time

	refreshMu sync.Mutex
}

// RemoteOpt configures a Remote at construction.
type RemoteOpt func(*Remote)

// WithHTTPClient overrides the default *http.Client used to fetch the JWKS.
func WithHTTPClient(c *http.Client) RemoteOpt {
	return func(r *Remote) {
		if c != nil {
			r.client = c
		}
	}
}

// WithTTL overrides the cache lifetime. Zero or negative values fall back to DefaultRemoteTTL.
func WithTTL(d time.Duration) RemoteOpt {
	return func(r *Remote) {
		if d > 0 {
			r.ttl = d
		}
	}
}

// NewRemote returns a Remote that fetches the JWKS from url.
func NewRemote(url string, opts ...RemoteOpt) (*Remote, error) {
	if strings.TrimSpace(url) == "" {
		return nil, fmt.Errorf("%w: url cannot be empty", pkgerr.ErrInvalidValue)
	}
	r := &Remote{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
		ttl:    DefaultRemoteTTL,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// KeySet returns the cached KeySet, fetching from the remote if the cache is empty or expired.
func (r *Remote) KeySet(ctx context.Context) (*KeySet, error) {

	r.mu.RLock()
	if r.cached != nil && time.Now().Before(r.expiresAt) {
		ks := r.cached
		r.mu.RUnlock()
		return ks, nil
	}
	r.mu.RUnlock()

	return r.cachedOrFetch(ctx)
}

// PublicKey returns the public key for the given kid, refreshing the cache if needed.
func (r *Remote) PublicKey(ctx context.Context, kid string) (any, error) {
	ks, err := r.KeySet(ctx)
	if err != nil {
		return nil, err
	}
	return ks.PublicKey(kid)
}

// Refresh forces a fetch, replacing the cached KeySet on success.
func (r *Remote) Refresh(ctx context.Context) (*KeySet, error) {
	return r.fetch(ctx)
}

// cachedOrFetch coalesces concurrent KeySet callers — late winners see the cache populated
// by the first fetcher and return without issuing another HTTP request.
func (r *Remote) cachedOrFetch(ctx context.Context) (*KeySet, error) {

	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()

	r.mu.RLock()
	if r.cached != nil && time.Now().Before(r.expiresAt) {
		ks := r.cached
		r.mu.RUnlock()
		return ks, nil
	}
	r.mu.RUnlock()

	return r.fetchLocked(ctx)
}

// fetch always performs an HTTP fetch, replacing the cache on success.
func (r *Remote) fetch(ctx context.Context) (*KeySet, error) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	return r.fetchLocked(ctx)
}

// fetchLocked performs the HTTP request. Caller must hold refreshMu.
func (r *Remote) fetchLocked(ctx context.Context) (*KeySet, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building jwks request: %w", pkgerr.ErrInvalidValue, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetching jwks: %w", pkgerr.ErrRead, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: jwks fetch returned status %d", pkgerr.ErrRead, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading jwks response: %w", pkgerr.ErrRead, err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("%w: decoding jwks json: %w", pkgerr.ErrDecode, err)
	}

	ks, err := FromJWKS(jwks)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.cached = ks
	r.expiresAt = time.Now().Add(r.ttl)
	r.mu.Unlock()

	return ks, nil
}
