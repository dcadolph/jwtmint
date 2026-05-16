package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// DefaultRemoteTTL is the cache lifetime applied when none is provided.
const DefaultRemoteTTL = 10 * time.Minute

// DefaultNegativeTTL is how long a fetch failure is remembered to avoid hammering an
// upstream that is down. Successful refreshes clear the negative cache.
const DefaultNegativeTTL = 30 * time.Second

// DefaultMaxBodyBytes caps the response body size when fetching the JWKS.
//
// 1 MiB comfortably accommodates dozens of keys; larger payloads are almost certainly
// abuse or misconfiguration.
const DefaultMaxBodyBytes int64 = 1 << 20

// Remote fetches a JWKS from a URL, caching the result for a configurable TTL.
//
// Lookup returns the cached set when fresh; on miss or expiry it fetches and atomically
// swaps. Concurrent callers during a refresh share a single in-flight request via the
// embedded singleflight-like guard, avoiding stampedes. Failed fetches are remembered
// for NegativeTTL so an upstream outage does not amplify into a request flood.
//
// By default Remote honors the server's Cache-Control: max-age directive: when present
// the per-fetch TTL is min(configured TTL, server max-age). Disable via WithIgnoreCacheControl
// when you intentionally want to override servers that under-cache.
type Remote struct {
	url                string
	client             *http.Client
	ttl                time.Duration
	negativeTTL        time.Duration
	maxBodyBytes       int64
	ignoreCacheControl bool

	mu        sync.RWMutex
	cached    *KeySet
	expiresAt time.Time
	lastErr   error
	errAt     time.Time

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

// WithNegativeTTL sets how long a fetch failure is cached. Zero disables negative caching.
func WithNegativeTTL(d time.Duration) RemoteOpt {
	return func(r *Remote) {
		if d >= 0 {
			r.negativeTTL = d
		}
	}
}

// WithMaxBodyBytes caps the response body size. Zero or negative values keep the default.
func WithMaxBodyBytes(n int64) RemoteOpt {
	return func(r *Remote) {
		if n > 0 {
			r.maxBodyBytes = n
		}
	}
}

// WithIgnoreCacheControl disables honoring of the server's Cache-Control: max-age directive.
//
// Default behavior: per-fetch TTL is min(configured TTL, server max-age). With this opt,
// the configured TTL is always used regardless of what the server returns.
func WithIgnoreCacheControl() RemoteOpt {
	return func(r *Remote) {
		r.ignoreCacheControl = true
	}
}

// NewRemote returns a Remote that fetches the JWKS from url.
func NewRemote(url string, opts ...RemoteOpt) (*Remote, error) {
	if strings.TrimSpace(url) == "" {
		return nil, fmt.Errorf("%w: url cannot be empty", pkgerr.ErrInvalidValue)
	}
	r := &Remote{
		url:          url,
		client:       &http.Client{Timeout: 10 * time.Second},
		ttl:          DefaultRemoteTTL,
		negativeTTL:  DefaultNegativeTTL,
		maxBodyBytes: DefaultMaxBodyBytes,
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
// by the first fetcher and return without issuing another HTTP request. Honors the
// negative cache: a recent failure short-circuits without re-fetching.
func (r *Remote) cachedOrFetch(ctx context.Context) (*KeySet, error) {

	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()

	r.mu.RLock()
	if r.cached != nil && time.Now().Before(r.expiresAt) {
		ks := r.cached
		r.mu.RUnlock()
		return ks, nil
	}
	if r.lastErr != nil && r.negativeTTL > 0 && time.Since(r.errAt) < r.negativeTTL {
		err := r.lastErr
		r.mu.RUnlock()
		return nil, fmt.Errorf("%w (negative cache; recent fetch failed)", err)
	}
	r.mu.RUnlock()

	return r.fetchLocked(ctx)
}

// fetch always performs an HTTP fetch, replacing the cache on success.
//
// Bypasses the negative cache — explicit refresh ignores prior failures.
func (r *Remote) fetch(ctx context.Context) (*KeySet, error) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	return r.fetchLocked(ctx)
}

// fetchLocked performs the HTTP request. Caller must hold refreshMu.
//
// Records the result (success clears errors; failure is remembered for the negative TTL).
// When the server returned a Cache-Control: max-age directive smaller than the configured
// TTL, the cache lifetime for this fetch is shortened accordingly.
func (r *Remote) fetchLocked(ctx context.Context) (*KeySet, error) {

	ks, ttl, err := r.doFetch(ctx)

	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.lastErr = err
		r.errAt = time.Now()
		return nil, err
	}
	r.cached = ks
	r.expiresAt = time.Now().Add(ttl)
	r.lastErr = nil
	return ks, nil
}

// doFetch issues one HTTP request, capping the response body and decoding the JWKS.
//
// Returns the KeySet and the TTL to apply to it: the configured TTL by default, or
// min(configured, server max-age) when the server provided a smaller Cache-Control
// directive (and ignoreCacheControl is false).
func (r *Remote) doFetch(ctx context.Context) (*KeySet, time.Duration, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: building jwks request: %w", pkgerr.ErrInvalidValue, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: fetching jwks: %w", pkgerr.ErrRead, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("%w: jwks fetch returned status %d", pkgerr.ErrRead, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, r.maxBodyBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: reading jwks response: %w", pkgerr.ErrRead, err)
	}
	if int64(len(body)) > r.maxBodyBytes {
		return nil, 0, fmt.Errorf("%w: jwks response body exceeds %d bytes", pkgerr.ErrRead, r.maxBodyBytes)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, 0, fmt.Errorf("%w: decoding jwks json: %w", pkgerr.ErrDecode, err)
	}

	ks, err := FromJWKS(jwks)
	if err != nil {
		return nil, 0, err
	}

	ttl := r.ttl
	if !r.ignoreCacheControl {
		if maxAge, ok := parseCacheControlMaxAge(resp.Header.Get("Cache-Control")); ok && maxAge < ttl {
			ttl = maxAge
		}
	}
	return ks, ttl, nil
}

// parseCacheControlMaxAge extracts the max-age directive from a Cache-Control header.
//
// Returns the parsed duration and true on success; (0, false) when no usable max-age
// directive is present. Negative or unparseable values yield (0, false). Honors
// no-store / no-cache by returning (0, false) since "do not cache" is incompatible with
// the JWKS fetch model — callers fall back to the configured TTL in that case.
func parseCacheControlMaxAge(header string) (time.Duration, bool) {
	if header == "" {
		return 0, false
	}
	for _, raw := range strings.Split(header, ",") {
		directive := strings.TrimSpace(raw)
		if directive == "" {
			continue
		}
		lower := strings.ToLower(directive)
		if lower == "no-store" || lower == "no-cache" {
			return 0, false
		}
		const prefix = "max-age="
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		secs, err := strconv.Atoi(strings.TrimSpace(directive[len(prefix):]))
		if err != nil || secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	return 0, false
}
