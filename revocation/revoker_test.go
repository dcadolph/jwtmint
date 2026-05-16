package revocation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/pkgerr"
)

// tokenWith returns a parsed *jwt.Token (unsigned shell) carrying the given claims.
func tokenWith(c jwt.MapClaims) *jwt.Token {
	return &jwt.Token{Claims: c, Header: map[string]any{}}
}

// TestMemRevokerJTI covers the default JTI extractor across revoke / unrevoke / TTL paths.
func TestMemRevokerJTI(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	r, err := NewMemRevoker(WithClock(clock))
	if err != nil {
		t.Fatalf("NewMemRevoker: %v", err)
	}

	revoked := tokenWith(jwt.MapClaims{claims.KeyID: "jti-1"})
	other := tokenWith(jwt.MapClaims{claims.KeyID: "jti-2"})
	noJTI := tokenWith(jwt.MapClaims{claims.KeySubject: "u1"})

	r.Revoke("jti-1")
	r.RevokeUntil("jti-3", now.Add(time.Hour))
	r.RevokeUntil("jti-expired", now.Add(-time.Second))

	tests := []struct {
		Name    string
		Token   *jwt.Token
		Want    bool
	}{
		{Name: "indefinitely revoked", Token: revoked, Want: true},
		{Name: "different jti not revoked", Token: other, Want: false},
		{Name: "no jti is not revoked", Token: noJTI, Want: false},
		{Name: "ttl in future", Token: tokenWith(jwt.MapClaims{claims.KeyID: "jti-3"}), Want: true},
		{Name: "ttl in past", Token: tokenWith(jwt.MapClaims{claims.KeyID: "jti-expired"}), Want: false},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got, err := r.Revoked(context.Background(), test.Token)
			if err != nil {
				t.Fatalf("Revoked: %v", err)
			}
			if got != test.Want {
				t.Errorf("want %v got %v", test.Want, got)
			}
		})
	}
}

// TestMemRevokerUnrevoke checks that Unrevoke removes a previously-revoked entry.
func TestMemRevokerUnrevoke(t *testing.T) {
	t.Parallel()

	r, _ := NewMemRevoker()
	tok := tokenWith(jwt.MapClaims{claims.KeyID: "jti-toggle"})

	r.Revoke("jti-toggle")
	if got, _ := r.Revoked(context.Background(), tok); !got {
		t.Fatalf("after Revoke: want true got false")
	}
	r.Unrevoke("jti-toggle")
	if got, _ := r.Revoked(context.Background(), tok); got {
		t.Errorf("after Unrevoke: want false got true")
	}
}

// TestMemRevokerCleanup checks that Cleanup reaps only past-expiry entries.
func TestMemRevokerCleanup(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r, _ := NewMemRevoker(WithClock(func() time.Time { return now }))

	r.Revoke("forever")
	r.RevokeUntil("future", now.Add(time.Hour))
	r.RevokeUntil("past-1", now.Add(-time.Second))
	r.RevokeUntil("past-2", now.Add(-time.Hour))

	if got := r.Cleanup(); got != 2 {
		t.Errorf("Cleanup: want 2 removed, got %d", got)
	}
	if got := r.Len(); got != 2 {
		t.Errorf("Len after Cleanup: want 2 got %d", got)
	}
}

// TestMemRevokerSubjectExtractor covers revoking by sub instead of jti.
func TestMemRevokerSubjectExtractor(t *testing.T) {
	t.Parallel()

	r, err := NewMemRevoker(WithKeyExtractor(SubjectExtractor))
	if err != nil {
		t.Fatalf("NewMemRevoker: %v", err)
	}
	r.Revoke("user-x")

	tok := tokenWith(jwt.MapClaims{claims.KeySubject: "user-x", claims.KeyID: "any"})
	got, err := r.Revoked(context.Background(), tok)
	if err != nil {
		t.Fatalf("Revoked: %v", err)
	}
	if !got {
		t.Errorf("subject-revoked token: want true got false")
	}
}

// TestMemRevokerConstructorErrors covers nil-arg rejection on the opt constructors.
func TestMemRevokerConstructorErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name string
		Opt  MemOpt
	}{
		{Name: "nil extractor", Opt: WithKeyExtractor(nil)},
		{Name: "nil clock", Opt: WithClock(nil)},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			_, err := NewMemRevoker(test.Opt)
			if !errors.Is(err, pkgerr.ErrInvalidValue) {
				t.Errorf("want ErrInvalidValue got %v", err)
			}
		})
	}
}

// TestChain checks ordering, short-circuit on revoked, and short-circuit on error.
func TestChain(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("backend down")

	always := RevokerFunc(func(_ context.Context, _ *jwt.Token) (bool, error) { return true, nil })
	never := RevokerFunc(func(_ context.Context, _ *jwt.Token) (bool, error) { return false, nil })
	boom := RevokerFunc(func(_ context.Context, _ *jwt.Token) (bool, error) { return false, sentinel })

	tests := []struct {
		Name     string
		Chain    Revoker
		WantBool bool
		WantErr  error
	}{
		{Name: "all never", Chain: Chain(never, never)},
		{Name: "first always wins", Chain: Chain(always, boom), WantBool: true},
		{Name: "error short-circuits", Chain: Chain(never, boom), WantErr: sentinel},
		{Name: "nil entries skipped", Chain: Chain(nil, never, nil)},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got, err := test.Chain.Revoked(context.Background(), tokenWith(jwt.MapClaims{}))
			if test.WantErr != nil {
				if !errors.Is(err, test.WantErr) {
					t.Errorf("want err %v got %v", test.WantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != test.WantBool {
				t.Errorf("want %v got %v", test.WantBool, got)
			}
		})
	}
}
