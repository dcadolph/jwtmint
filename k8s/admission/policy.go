// Package admission implements a Kubernetes ValidatingAdmissionWebhook that gates
// JWTRequest creation/update by the requester's identity.
//
// SelfOnlyPolicy default semantics:
//   - Subject must equal requester.Username (or be empty).
//   - Every requested Group must appear in requester.Groups.
//   - Every requested Role must appear in AllowedRoles (deny-all when AllowedRoles is empty).
//   - Every requested Audience must appear in AllowedAudiences (deny-all when empty).
//   - Every requested Entitlement must appear in AllowedEntitlements (deny-all when empty).
//   - Every key in ExtraClaims must appear in AllowedExtraClaimKeys (deny-all when empty).
//   - AdminUsers / AdminGroups bypass every check above.
//
// Default-deny is the safe stance: an empty allow-list rejects all requests for that
// field. This prevents accidental privilege escalation when the operator forgot to scope
// a category. To explicitly allow anything in a category, populate the allow-list with
// the literal "*".
package admission

import (
	"fmt"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"

	v1alpha1 "github.com/dcadolph/jwtmint/k8s/api/v1alpha1"
	"github.com/dcadolph/jwtmint/pkgerr"
)

// AllowAny is the literal value that, when present in any AllowedX list, opts out of
// default-deny for that category and allows arbitrary values.
const AllowAny = "*"

// Policy decides whether a JWTRequest from a given requester should be admitted.
//
// Returning a non-nil error rejects the request; the error's message is included in
// the AdmissionResponse status as the rejection reason. Implementations should write
// reasons that are safe to expose to the requester.
type Policy interface {
	Allow(requester authnv1.UserInfo, jr *v1alpha1.JWTRequest) error
}

// PolicyFunc adapts a function to the Policy interface.
type PolicyFunc func(requester authnv1.UserInfo, jr *v1alpha1.JWTRequest) error

// Allow calls the receiver, implementing Policy.
func (f PolicyFunc) Allow(requester authnv1.UserInfo, jr *v1alpha1.JWTRequest) error {
	return f(requester, jr)
}

// SelfOnlyPolicy is the default policy: see package doc for full semantics.
type SelfOnlyPolicy struct {
	// AllowedAudiences caps which "aud" values JWTRequests may request.
	// Empty list defaults to deny-all. Use AllowAny ("*") to allow arbitrary values.
	AllowedAudiences []string
	// AllowedEntitlements caps which "entitlements" values may be requested.
	// Empty list defaults to deny-all. Use AllowAny ("*") to allow arbitrary values.
	AllowedEntitlements []string
	// AllowedRoles caps which "roles" values may be requested.
	// Empty list defaults to deny-all. Use AllowAny ("*") to allow arbitrary values.
	AllowedRoles []string
	// AllowedExtraClaimKeys caps which extraClaim keys may be set.
	// Empty list defaults to deny-all. Use AllowAny ("*") to allow arbitrary keys.
	AllowedExtraClaimKeys []string
	// AdminUsers bypass all policy checks (e.g. break-glass operators).
	AdminUsers []string
	// AdminGroups bypass all policy checks.
	AdminGroups []string
}

// Allow implements Policy.
func (p *SelfOnlyPolicy) Allow(requester authnv1.UserInfo, jr *v1alpha1.JWTRequest) error {

	if jr == nil {
		return fmt.Errorf("%w: JWTRequest is nil", pkgerr.ErrInvalidValue)
	}

	if isAdmin(p, requester) {
		return nil
	}

	if jr.Spec.Subject != "" && jr.Spec.Subject != requester.Username {
		return fmt.Errorf(
			"spec.subject %q does not match requester username %q",
			jr.Spec.Subject, requester.Username,
		)
	}

	requesterGroups := stringSet(requester.Groups)
	for _, g := range jr.Spec.Groups {
		if !requesterGroups[g] {
			return fmt.Errorf("spec.groups[%q] is not in requester's groups", g)
		}
	}

	if err := checkAllowedList("spec.audience", jr.Spec.Audience, p.AllowedAudiences); err != nil {
		return err
	}
	if err := checkAllowedList("spec.entitlements", jr.Spec.Entitlements, p.AllowedEntitlements); err != nil {
		return err
	}
	if err := checkAllowedList("spec.roles", jr.Spec.Roles, p.AllowedRoles); err != nil {
		return err
	}
	if err := checkAllowedKeys("spec.extraClaims", jr.Spec.ExtraClaims, p.AllowedExtraClaimKeys); err != nil {
		return err
	}

	return nil
}

// checkAllowedList rejects when requested contains values outside allowed.
//
// Empty allowed list is deny-all unless requested is also empty (nothing to deny).
// AllowAny in allowed opts out of deny-all and accepts any value.
func checkAllowedList(field string, requested, allowed []string) error {
	if len(requested) == 0 {
		return nil
	}
	if containsString(allowed, AllowAny) {
		return nil
	}
	if len(allowed) == 0 {
		return fmt.Errorf("%s requested but no allow-list configured (default deny)", field)
	}
	allowedSet := stringSet(allowed)
	for _, r := range requested {
		if !allowedSet[r] {
			return fmt.Errorf("%s[%q] is not in the allow-list", field, r)
		}
	}
	return nil
}

// checkAllowedKeys rejects when requested has keys outside allowed.
//
// Empty allowed is deny-all unless requested is empty. AllowAny opts out. Generic over
// the value type so callers may pass any map shape (map[string]string,
// map[string]apiextensionsv1.JSON, etc.) — only the keys are inspected.
func checkAllowedKeys[V any](field string, requested map[string]V, allowed []string) error {
	if len(requested) == 0 {
		return nil
	}
	if containsString(allowed, AllowAny) {
		return nil
	}
	if len(allowed) == 0 {
		return fmt.Errorf("%s requested but no allow-list configured (default deny)", field)
	}
	allowedSet := stringSet(allowed)
	for k := range requested {
		if !allowedSet[k] {
			return fmt.Errorf("%s[%q] is not in the allow-list", field, k)
		}
	}
	return nil
}

// containsString reports whether s contains v.
func containsString(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

// isAdmin reports whether the requester matches an AdminUsers or AdminGroups entry.
func isAdmin(p *SelfOnlyPolicy, requester authnv1.UserInfo) bool {
	for _, u := range p.AdminUsers {
		if u == requester.Username {
			return true
		}
	}
	if len(p.AdminGroups) == 0 {
		return false
	}
	groups := stringSet(requester.Groups)
	for _, g := range p.AdminGroups {
		if groups[g] {
			return true
		}
	}
	return false
}

// stringSet returns a presence map for s.
func stringSet(s []string) map[string]bool {
	out := make(map[string]bool, len(s))
	for _, v := range s {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out[v] = true
	}
	return out
}
