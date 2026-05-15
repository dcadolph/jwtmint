package claims

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// TestRoundTripRegistered exercises set/get for each registered claim.
func TestRoundTripRegistered(t *testing.T) {
	t.Parallel()

	now := time.Unix(1700000000, 0)
	c := jwt.MapClaims{}

	SetID(c, "abc-123")
	SetIssuer(c, "iss-1")
	SetSubject(c, "sub-1")
	SetAudience(c, "aud-1", "aud-2")
	SetIssuedAt(c, now)
	SetExpiresAt(c, now.Add(time.Hour))
	SetNotBefore(c, now)

	if got, _ := ID(c); got != "abc-123" {
		t.Errorf("ID: want abc-123 got %q", got)
	}
	if got, _ := Issuer(c); got != "iss-1" {
		t.Errorf("Issuer: want iss-1 got %q", got)
	}
	if got, _ := Subject(c); got != "sub-1" {
		t.Errorf("Subject: want sub-1 got %q", got)
	}
	aud, _ := Audience(c)
	if diff := cmp.Diff([]string{"aud-1", "aud-2"}, aud); diff != "" {
		t.Errorf("Audience mismatch (-want +got):\n%s", diff)
	}
	iat, _ := IssuedAt(c)
	if !iat.Equal(now) {
		t.Errorf("IssuedAt: want %v got %v", now, iat)
	}
	exp, _ := ExpiresAt(c)
	if !exp.Equal(now.Add(time.Hour)) {
		t.Errorf("ExpiresAt: want %v got %v", now.Add(time.Hour), exp)
	}
	nbf, _ := NotBefore(c)
	if !nbf.Equal(now) {
		t.Errorf("NotBefore: want %v got %v", now, nbf)
	}
}

// TestAudienceTypes confirms Audience accepts the documented input types.
func TestAudienceTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		WantSlice []string
		Want      error
		Name      string
		Input     any
	}{
		{Name: "string slice", Input: []string{"a", "b"}, WantSlice: []string{"a", "b"}},
		{Name: "any slice", Input: []any{"a", "b"}, WantSlice: []string{"a", "b"}},
		{Name: "csv string", Input: "a,b", WantSlice: []string{"a", "b"}},
		{Name: "empty slice", Input: []string{}, Want: pkgerr.ErrEmptyValue},
		{Name: "wrong element type", Input: []any{"a", 1}, Want: pkgerr.ErrInvalidClaims},
		{Name: "wrong outer type", Input: 42, Want: pkgerr.ErrInvalidClaims},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			c := jwt.MapClaims{KeyAudience: test.Input}
			got, err := Audience(c)
			if !errors.Is(err, test.Want) {
				t.Fatalf("test %d: error mismatch\nwant: %v\ngot:  %v", testNum, test.Want, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.WantSlice, got, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("test %d: mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}

// TestMatchingAudience covers overlap, no-overlap, and missing-audience paths.
func TestMatchingAudience(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Want      error
		Name      string
		Have      []string
		Match     []string
		WantSlice []string
	}{
		{Name: "overlap", Have: []string{"a", "b"}, Match: []string{"b", "c"}, WantSlice: []string{"b"}},
		{Name: "no overlap", Have: []string{"a"}, Match: []string{"b"}, Want: ErrNoAudience},
		{Name: "missing aud", Have: nil, Match: []string{"a"}, Want: pkgerr.ErrNotFound},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			c := jwt.MapClaims{}
			if test.Have != nil {
				SetAudience(c, test.Have...)
			}
			got, err := MatchingAudience(c, test.Match...)
			if !errors.Is(err, test.Want) {
				t.Fatalf("test %d: error mismatch\nwant: %v\ngot:  %v", testNum, test.Want, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.WantSlice, got); diff != "" {
				t.Fatalf("test %d: mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}

// TestDeepCopy ensures mutating a copy does not affect the source.
func TestDeepCopy(t *testing.T) {
	t.Parallel()

	src := jwt.MapClaims{"a": 1}
	dst := DeepCopy(src)
	dst["a"] = 2
	if src["a"] != 1 {
		t.Errorf("src mutated by copy: got %v", src["a"])
	}
}

// TestIsRegisteredClaim covers known and unknown keys.
func TestIsRegisteredClaim(t *testing.T) {
	t.Parallel()

	for _, k := range []string{KeyExpiresAt, KeyIssuedAt, KeyNotBefore, KeyID, KeyIssuer, KeyAudience, KeySubject} {
		if !IsRegisteredClaim(k) {
			t.Errorf("IsRegisteredClaim(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"groups", "email", "", "custom"} {
		if IsRegisteredClaim(k) {
			t.Errorf("IsRegisteredClaim(%q) = true, want false", k)
		}
	}
}

// TestCheckFuncs covers the common claim checks.
func TestCheckFuncs(t *testing.T) {
	t.Parallel()

	now := time.Now()

	good := jwt.MapClaims{}
	SetIssuer(good, "issuer-x")
	SetAudience(good, "aud-x")
	SetGroups(good, "g1")
	SetRoles(good, "r1")
	SetExpiresAt(good, now.Add(time.Hour))
	SetNotBefore(good, now.Add(-time.Minute))

	tests := []struct {
		Check CheckFunc
		Want  error
		Name  string
		In    jwt.MapClaims
	}{
		{Name: "required keys present", Check: CheckRequiredKeys(KeyIssuer, KeyAudience), In: good},
		{Name: "required keys missing", Check: CheckRequiredKeys("never"), In: good, Want: pkgerr.ErrNotFound},
		{Name: "issuer allowed", Check: CheckIssuer("issuer-x"), In: good},
		{Name: "issuer rejected", Check: CheckIssuer("other"), In: good, Want: pkgerr.ErrCheck},
		{Name: "audience match", Check: CheckAudience("aud-x"), In: good},
		{Name: "audience miss", Check: CheckAudience("other"), In: good, Want: ErrNoAudience},
		{Name: "groups match", Check: CheckHasGroups("g1"), In: good},
		{Name: "groups miss", Check: CheckHasGroups("g2"), In: good, Want: ErrNoGroups},
		{Name: "roles match", Check: CheckHasRoles("r1"), In: good},
		{Name: "not expired ok", Check: CheckNotExpired(0), In: good},
		{Name: "not expired fail", Check: CheckNotExpired(0), In: pastClaims(), Want: pkgerr.ErrExpired},
		{Name: "nbf ready", Check: CheckNotBeforeReady(0), In: good},
		{Name: "nbf future", Check: CheckNotBeforeReady(0), In: futureNbf(), Want: pkgerr.ErrNotReady},
		{Name: "chain ok", Check: Chain(CheckIssuer("issuer-x"), CheckNotExpired(0)), In: good},
		{Name: "chain fail", Check: Chain(CheckIssuer("issuer-x"), CheckIssuer("other")), In: good, Want: pkgerr.ErrCheck},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			err := test.Check(context.Background(), test.In)
			if !errors.Is(err, test.Want) {
				t.Fatalf("test %d: error mismatch\nwant: %v\ngot:  %v", testNum, test.Want, err)
			}
		})
	}
}

func pastClaims() jwt.MapClaims {
	c := jwt.MapClaims{}
	SetExpiresAt(c, time.Now().Add(-time.Hour))
	return c
}

func futureNbf() jwt.MapClaims {
	c := jwt.MapClaims{}
	SetNotBefore(c, time.Now().Add(time.Hour))
	return c
}
