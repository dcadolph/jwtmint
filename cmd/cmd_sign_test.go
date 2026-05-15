package cmd

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/jwtsmith/claims"
)

// TestBuildClaims covers the merging of profile, JSON, and key=value claim sources.
func TestBuildClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Want    error
		Name    string
		Flags   *signFlags
		WantHas map[string]any
	}{
		{
			Name: "profile fields only",
			Flags: &signFlags{
				subject:      "u1",
				issuer:       "iss-1",
				audience:     []string{"a", "b"},
				groups:       []string{"g1"},
				roles:        []string{"r1"},
				entitlements: []string{"e1"},
				email:        "u1@example.com",
			},
			WantHas: map[string]any{
				claims.KeySubject:     "u1",
				claims.KeyIssuer:      "iss-1",
				claims.KeyEmail:       "u1@example.com",
				claims.KeyEntitlements: []string{"e1"},
			},
		},
		{
			Name: "json string overlay",
			Flags: &signFlags{
				subject:    "u1",
				claimsJSON: `{"tenant":"acme","email":"override@example.com"}`,
			},
			WantHas: map[string]any{
				claims.KeySubject: "u1",
				"tenant":          "acme",
				claims.KeyEmail:   "override@example.com",
			},
		},
		{
			Name: "key=value pairs",
			Flags: &signFlags{
				claimKV: []string{"env=prod", "region=us-east"},
			},
			WantHas: map[string]any{
				"env":    "prod",
				"region": "us-east",
			},
		},
		{
			Name: "malformed claim kv",
			Flags: &signFlags{
				claimKV: []string{"oops"},
			},
			Want: ErrUsage,
		},
		{
			Name: "malformed claims-json",
			Flags: &signFlags{
				claimsJSON: `not valid json`,
			},
			Want: cmpErrSentinel{}, // Wrapped error; only check non-nil below.
		},
	}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got, err := buildClaims(test.Flags)
			switch want := test.Want.(type) {
			case nil:
				if err != nil {
					t.Fatalf("test %d: unexpected error: %v", testNum, err)
				}
			case cmpErrSentinel:
				if err == nil {
					t.Fatalf("test %d: expected error, got nil", testNum)
				}
				return
			default:
				if !errors.Is(err, want) {
					t.Fatalf("test %d: error mismatch\nwant: %v\ngot:  %v", testNum, want, err)
				}
				return
			}
			for k, want := range test.WantHas {
				gv, ok := got[k]
				if !ok {
					t.Errorf("test %d: claim %q missing", testNum, k)
					continue
				}
				if diff := cmp.Diff(want, gv, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("test %d: claim %q mismatch (-want +got):\n%s", testNum, k, diff)
				}
			}
		})
	}
}

// cmpErrSentinel marks a test case where any non-nil error is acceptable.
type cmpErrSentinel struct{}

// Error satisfies the error interface so the sentinel can occupy the Want slot.
func (cmpErrSentinel) Error() string { return "any error" }
