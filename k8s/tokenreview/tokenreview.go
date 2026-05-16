// Package tokenreview implements a Kubernetes TokenReview webhook handler that
// validates JWTs using a jwtmint verification.Verifier.
//
// Wire the Handler into any net/http mux at the path the apiserver's --authentication-token-webhook-config
// kubeconfig points at. The handler decodes the inbound TokenReview request, verifies
// the spec.token field, and responds with a TokenReview whose status.authenticated and
// status.user fields reflect the outcome.
//
// JWT-to-UserInfo mapping (overridable via UserInfoMapper):
//   - sub claim       -> Username
//   - groups claim    -> Groups
//   - aud claim       -> Extra["aud"]
//   - jti claim       -> UID
//   - other claims    -> Extra["claim_<name>"] (single-value string conversion)
package tokenreview

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/internal/jsonutil"
	"github.com/dcadolph/jwtmint/pkgerr"
	"github.com/dcadolph/jwtmint/verification"
)

// UserInfoMapper translates verified JWT claims into a Kubernetes UserInfo.
//
// Implement to customize how claims map to user identity (e.g. choose a different
// claim for username, namespace groups by prefix, derive extras from custom claims).
// The default mapping is described on the package doc.
type UserInfoMapper func(c jwt.MapClaims) (authnv1.UserInfo, error)

// Opt configures the Handler at construction.
type Opt func(*config)

type config struct {
	extra        []verification.TokenCheckFunc
	claimsChecks []claims.CheckFunc
	mapper       UserInfoMapper
	audiences    []string
}

// WithCheck adds a TokenCheckFunc run after signature verification.
func WithCheck(checks ...verification.TokenCheckFunc) Opt {
	return func(c *config) { c.extra = append(c.extra, checks...) }
}

// WithClaimsCheck adds a claims.CheckFunc run after signature verification.
func WithClaimsCheck(checks ...claims.CheckFunc) Opt {
	return func(c *config) { c.claimsChecks = append(c.claimsChecks, checks...) }
}

// WithUserInfoMapper overrides the default claim-to-UserInfo translation.
func WithUserInfoMapper(m UserInfoMapper) Opt {
	return func(c *config) {
		if m != nil {
			c.mapper = m
		}
	}
}

// WithAudiences populates the audiences echoed in the TokenReview status when validation passes.
//
// When non-empty, only tokens whose aud claim contains at least one of these audiences are accepted.
func WithAudiences(audiences ...string) Opt {
	return func(c *config) { c.audiences = append(c.audiences, audiences...) }
}

// Handler returns an http.Handler that processes TokenReview POST requests.
//
// Panics on construction if v is nil — required dependency.
func Handler(v verification.Verifier, opts ...Opt) http.Handler {

	if v == nil {
		panic("tokenreview.Handler: verifier required")
	}

	cfg := config{mapper: DefaultUserInfoMapper}
	for _, opt := range opts {
		opt(&cfg)
	}
	if len(cfg.claimsChecks) > 0 {
		cfg.extra = append(cfg.extra, verification.CheckClaims(cfg.claimsChecks...))
	}
	if len(cfg.audiences) > 0 {
		cfg.extra = append(cfg.extra, verification.CheckClaims(claims.CheckAudience(cfg.audiences...)))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		const maxBody = 64 * 1024
		body := http.MaxBytesReader(w, r.Body, maxBody)

		var review authnv1.TokenReview
		if err := json.NewDecoder(body).Decode(&review); err != nil {
			writeReview(w, http.StatusBadRequest, deniedReview("invalid TokenReview body"))
			return
		}
		if review.Spec.Token == "" {
			writeReview(w, http.StatusBadRequest, deniedReview("spec.token required"))
			return
		}

		// Per the TokenReview contract, when the apiserver requests specific audiences,
		// the webhook must verify the token's aud claim against that set. Apply both the
		// constructor-time audiences and any in the request.
		extra := cfg.extra
		if len(review.Spec.Audiences) > 0 {
			extra = append(extra, verification.CheckClaims(claims.CheckAudience(review.Spec.Audiences...)))
		}

		tok, err := v.Verify(r.Context(), review.Spec.Token, extra...)
		if err != nil {
			writeReview(w, http.StatusOK, deniedReview("token did not validate"))
			return
		}

		mc, err := claims.ToMapClaims(tok.Claims)
		if err != nil {
			writeReview(w, http.StatusInternalServerError, deniedReview("internal error"))
			return
		}

		user, err := cfg.mapper(mc)
		if err != nil {
			writeReview(w, http.StatusInternalServerError, deniedReview("user mapper failed"))
			return
		}

		// Echo back the audiences the apiserver requested when present, else our configured set.
		respAudiences := review.Spec.Audiences
		if len(respAudiences) == 0 {
			respAudiences = cfg.audiences
		}

		out := review.DeepCopy()
		out.Status = authnv1.TokenReviewStatus{
			Authenticated: true,
			User:          user,
			Audiences:     respAudiences,
		}
		out.Spec.Token = "" // Don't echo the token back.
		writeReview(w, http.StatusOK, *out)
	})
}

// DefaultUserInfoMapper implements the standard claim-to-UserInfo translation
// described in the package doc.
func DefaultUserInfoMapper(c jwt.MapClaims) (authnv1.UserInfo, error) {

	user := authnv1.UserInfo{Extra: map[string]authnv1.ExtraValue{}}

	if sub, err := claims.Subject(c); err == nil {
		user.Username = sub
	}
	if jti, err := claims.ID(c); err == nil {
		user.UID = jti
	}
	if groups, err := claims.Groups(c); err == nil {
		user.Groups = groups
	}
	if aud, err := claims.Audience(c); err == nil {
		user.Extra["aud"] = aud
	}

	for k, v := range c {
		if claims.IsRegisteredClaim(k) || k == claims.KeyGroups {
			continue
		}
		switch val := v.(type) {
		case string:
			user.Extra["claim_"+k] = authnv1.ExtraValue{val}
		case []string:
			user.Extra["claim_"+k] = authnv1.ExtraValue(val)
		case []any:
			ev := make(authnv1.ExtraValue, 0, len(val))
			for _, item := range val {
				if s, ok := item.(string); ok {
					ev = append(ev, s)
				}
			}
			if len(ev) > 0 {
				user.Extra["claim_"+k] = ev
			}
		}
	}

	if user.Username == "" {
		return user, fmt.Errorf("%w: username could not be derived from sub claim", pkgerr.ErrInvalidClaims)
	}
	return user, nil
}

// deniedReview builds a TokenReview status indicating authentication failure.
func deniedReview(reason string) authnv1.TokenReview {
	return authnv1.TokenReview{
		TypeMeta: metav1.TypeMeta{Kind: "TokenReview", APIVersion: "authentication.k8s.io/v1"},
		Status: authnv1.TokenReviewStatus{
			Authenticated: false,
			Error:         reason,
		},
	}
}

// writeReview marshals tr and writes it with the given status code.
func writeReview(w http.ResponseWriter, status int, tr authnv1.TokenReview) {
	_ = jsonutil.Write(w, status, tr)
}
