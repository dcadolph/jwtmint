package admission

import (
	"errors"
	"fmt"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"

	v1alpha1 "github.com/dcadolph/jwtsmith/k8s/api/v1alpha1"
)

// TestSelfOnlyPolicy covers the canonical accept/reject paths.
func TestSelfOnlyPolicy(t *testing.T) {
	t.Parallel()

	policy := &SelfOnlyPolicy{
		AllowedAudiences:    []string{"api", "internal"},
		AllowedEntitlements: []string{"billing.read"},
		AdminUsers:          []string{"admin"},
		AdminGroups:         []string{"sre"},
	}

	tests := []struct {
		User       authnv1.UserInfo
		Spec       v1alpha1.JWTRequestSpec
		Name       string
		ExpectFail bool
	}{
		{
			Name:       "subject matches user",
			User:       authnv1.UserInfo{Username: "alice", Groups: []string{"devs"}},
			Spec:       v1alpha1.JWTRequestSpec{Subject: "alice", Groups: []string{"devs"}, Audience: []string{"api"}, Entitlements: []string{"billing.read"}},
			ExpectFail: false,
		},
		{
			Name:       "subject mismatch",
			User:       authnv1.UserInfo{Username: "alice"},
			Spec:       v1alpha1.JWTRequestSpec{Subject: "bob"},
			ExpectFail: true,
		},
		{
			Name:       "group not held",
			User:       authnv1.UserInfo{Username: "alice", Groups: []string{"devs"}},
			Spec:       v1alpha1.JWTRequestSpec{Groups: []string{"admins"}},
			ExpectFail: true,
		},
		{
			Name:       "audience not allowed",
			User:       authnv1.UserInfo{Username: "alice"},
			Spec:       v1alpha1.JWTRequestSpec{Audience: []string{"public"}},
			ExpectFail: true,
		},
		{
			Name:       "entitlement not allowed",
			User:       authnv1.UserInfo{Username: "alice"},
			Spec:       v1alpha1.JWTRequestSpec{Entitlements: []string{"billing.write"}},
			ExpectFail: true,
		},
		{
			Name:       "admin user bypass",
			User:       authnv1.UserInfo{Username: "admin"},
			Spec:       v1alpha1.JWTRequestSpec{Subject: "alice", Groups: []string{"admins"}, Audience: []string{"public"}, Entitlements: []string{"anything"}},
			ExpectFail: false,
		},
		{
			Name:       "admin group bypass",
			User:       authnv1.UserInfo{Username: "operator", Groups: []string{"sre"}},
			Spec:       v1alpha1.JWTRequestSpec{Subject: "alice", Groups: []string{"admins"}},
			ExpectFail: false,
		},
		{
			Name:       "no claims requested ok",
			User:       authnv1.UserInfo{Username: "alice"},
			Spec:       v1alpha1.JWTRequestSpec{SecretName: "tok-1"},
			ExpectFail: false,
		},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			jr := &v1alpha1.JWTRequest{Spec: test.Spec}
			err := policy.Allow(test.User, jr)
			if test.ExpectFail && err == nil {
				t.Errorf("expected rejection, got nil")
			}
			if !test.ExpectFail && err != nil {
				t.Errorf("expected accept, got %v", err)
			}
		})
	}

	// Sanity check: nil JWTRequest is a hard error, not a policy decision.
	if err := policy.Allow(authnv1.UserInfo{}, nil); err == nil {
		t.Error("nil JWTRequest should error")
	} else if !errors.Is(err, errBaseSentinel{}) && err.Error() == "" {
		t.Error("nil JWTRequest error should have a message")
	}
}

// errBaseSentinel exists only so the comparison above compiles; the test never matches it.
type errBaseSentinel struct{}

func (errBaseSentinel) Error() string { return "" }
