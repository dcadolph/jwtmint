package httpauth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewRoundTripperAttachesBearer confirms outbound requests carry the bearer header.
func TestNewRoundTripperAttachesBearer(t *testing.T) {
	t.Parallel()

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	client := NewClient(StaticTokenSource{Value: "abc-123"}, nil)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if got != "Bearer abc-123" {
		t.Errorf("Authorization header: want 'Bearer abc-123', got %q", got)
	}
}

// TestFileTokenSourceRefresh verifies the file is re-read after RefreshInterval.
func TestFileTokenSourceRefresh(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "tok")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	src := &FileTokenSource{Path: path, RefreshInterval: 10 * time.Millisecond}

	got, err := src.Token()
	if err != nil || got != "v1" {
		t.Fatalf("first read: got %q err=%v", got, err)
	}

	if err := os.WriteFile(path, []byte("v2"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Within RefreshInterval, the cached value persists.
	if got, _ := src.Token(); got != "v1" {
		t.Errorf("cached read: want v1 got %q", got)
	}

	time.Sleep(15 * time.Millisecond)
	if got, _ := src.Token(); got != "v2" {
		t.Errorf("after refresh: want v2 got %q", got)
	}
}

// TestCachedTokenSource confirms the cached value is reused within TTL and refreshed after.
func TestCachedTokenSource(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	inner := TokenSourceFunc(func() (string, error) {
		n := calls.Add(1)
		if n == 1 {
			return "first", nil
		}
		return "second", nil
	})

	cached := &CachedTokenSource{Source: inner, TTL: 20 * time.Millisecond}
	if got, _ := cached.Token(); got != "first" {
		t.Errorf("call 1: want first got %q", got)
	}
	if got, _ := cached.Token(); got != "first" {
		t.Errorf("call 2 (cached): want first got %q", got)
	}
	time.Sleep(25 * time.Millisecond)
	if got, _ := cached.Token(); got != "second" {
		t.Errorf("call 3 (refreshed): want second got %q", got)
	}
}
