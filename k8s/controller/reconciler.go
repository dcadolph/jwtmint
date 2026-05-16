// Package controller implements the controller-runtime reconciler that watches
// JWTRequest resources and maintains a Secret holding a freshly minted JWT.
//
// Reconciliation logic:
//   - If the Secret is missing, mint a token and create the Secret.
//   - If the Secret exists but the token has less than RefreshThreshold of its lifetime
//     remaining, mint a new token and update the Secret.
//   - Otherwise, requeue when the next refresh would be needed.
//
// Status fields (LastMintedAt, ExpiresAt, JTI, Conditions) are updated on every reconcile.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/dcadolph/jwtmint/claims"
	v1alpha1 "github.com/dcadolph/jwtmint/k8s/api/v1alpha1"
	"github.com/dcadolph/jwtmint/signing"
)

// SecretDataKey is the key under which the minted token is stored in the Secret.
const SecretDataKey = "token"

// DefaultRefreshThreshold is used when JWTRequest.Spec.RefreshThreshold is unset.
const DefaultRefreshThreshold = 0.25

// JWTRequestReconciler reconciles JWTRequest resources into Secrets holding fresh tokens.
type JWTRequestReconciler struct {
	// Client is the controller-runtime k8s client. Required.
	Client client.Client
	// Signer mints the actual tokens. Required.
	Signer signing.Signer
	// DefaultExpiration is applied when JWTRequest.Spec.ExpiresIn is empty.
	DefaultExpiration time.Duration
}

// SetupWithManager registers the reconciler with the given manager.
func (r *JWTRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.JWTRequest{}).
		Owns(&corev1.Secret{}, builder.MatchEveryOwner).
		Complete(r)
}

// Reconcile implements reconcile.Reconciler.
func (r *JWTRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	logger := log.FromContext(ctx)

	var jr v1alpha1.JWTRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &jr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get JWTRequest: %w", err)
	}

	if jr.Spec.SecretName == "" {
		r.setFailed(&jr, "spec.secretName required")
		return ctrl.Result{}, r.updateStatus(ctx, &jr)
	}

	expiration, err := resolveExpiration(jr.Spec.ExpiresIn, r.DefaultExpiration)
	if err != nil {
		r.setFailed(&jr, err.Error())
		return ctrl.Result{}, r.updateStatus(ctx, &jr)
	}

	threshold := DefaultRefreshThreshold
	if jr.Spec.RefreshThreshold != nil && *jr.Spec.RefreshThreshold > 0 && *jr.Spec.RefreshThreshold <= 1 {
		threshold = *jr.Spec.RefreshThreshold
	}

	secret, err := r.getSecret(ctx, jr.Namespace, jr.Spec.SecretName)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("get Secret: %w", err)
	}

	needsRefresh, requeueAfter := evaluateRefresh(secret, expiration, threshold)
	if !needsRefresh && secret != nil {
		logger.V(1).Info("token still fresh", "requeue", requeueAfter)
		jr.Status.SecretName = secret.Name
		return ctrl.Result{RequeueAfter: requeueAfter}, r.updateStatus(ctx, &jr)
	}

	signed, parsed, mintRes, err := r.mint(ctx, &jr, expiration)
	if err != nil {
		r.setFailed(&jr, err.Error())
		return ctrl.Result{}, r.updateStatus(ctx, &jr)
	}

	if err := r.upsertSecret(ctx, &jr, signed); err != nil {
		r.setFailed(&jr, err.Error())
		return ctrl.Result{}, r.updateStatus(ctx, &jr)
	}

	mc, _ := claims.ToMapClaims(parsed.Claims)
	expiresAt, _ := claims.ExpiresAt(mc)
	jti, _ := claims.ID(mc)

	now := metav1.Now()
	exp := metav1.NewTime(expiresAt)
	jr.Status.LastMintedAt = &now
	jr.Status.ExpiresAt = &exp
	jr.Status.JTI = jti
	jr.Status.SecretName = jr.Spec.SecretName
	jr.Status.ObservedGeneration = jr.Generation
	r.setMinted(&jr, secret == nil)
	r.setClaimsAccepted(&jr, mintRes)

	requeueAfter = nextRefresh(expiresAt, expiration, threshold)
	logger.Info("minted token", "secret", jr.Spec.SecretName, "exp", expiresAt, "requeue", requeueAfter)

	return ctrl.Result{RequeueAfter: requeueAfter}, r.updateStatus(ctx, &jr)
}

// claimDropReason classifies why an extraClaims entry was not used.
type claimDropReason int

const (
	claimDropReserved claimDropReason = iota // RFC 7519 registered claim key.
	claimDropInvalid                         // value isn't valid JSON.
)

// mintResult carries everything the caller needs to update status, including which
// extraClaims entries (if any) were rejected and why.
type mintResult struct {
	dropped map[claimDropReason][]string
}

// mint builds the claim set from the JWTRequest spec and signs it via the configured
// Signer. Returns the signed token, the parsed token, and a mintResult enumerating any
// extraClaims entries that were rejected (registered keys or invalid JSON values).
func (r *JWTRequestReconciler) mint(ctx context.Context, jr *v1alpha1.JWTRequest, expiration time.Duration) (string, *jwt.Token, mintResult, error) {

	c := jwt.MapClaims{}

	if jr.Spec.Subject != "" {
		claims.SetSubject(c, jr.Spec.Subject)
	}
	if jr.Spec.Issuer != "" {
		claims.SetIssuer(c, jr.Spec.Issuer)
	}
	if len(jr.Spec.Audience) > 0 {
		claims.SetAudience(c, jr.Spec.Audience...)
	}
	if len(jr.Spec.Groups) > 0 {
		claims.SetGroups(c, jr.Spec.Groups...)
	}
	if len(jr.Spec.Roles) > 0 {
		claims.SetRoles(c, jr.Spec.Roles...)
	}
	if len(jr.Spec.Entitlements) > 0 {
		claims.SetEntitlements(c, jr.Spec.Entitlements...)
	}
	res := mintResult{dropped: map[claimDropReason][]string{}}
	for k, raw := range jr.Spec.ExtraClaims {
		if claims.IsRegisteredClaim(k) {
			res.dropped[claimDropReserved] = append(res.dropped[claimDropReserved], k)
			continue
		}
		var v any
		if err := json.Unmarshal(raw.Raw, &v); err != nil {
			res.dropped[claimDropInvalid] = append(res.dropped[claimDropInvalid], k)
			continue
		}
		c[k] = v
	}
	for _, list := range res.dropped {
		sort.Strings(list)
	}
	claims.SetExpiresAt(c, time.Now().Add(expiration))

	signed, parsed, err := r.Signer.Sign(ctx, c, nil)
	return signed, parsed, res, err
}

// getSecret returns the Secret if it exists, or nil + nil error if it does not.
func (r *JWTRequestReconciler) getSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	var s corev1.Secret
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &s); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
}

// upsertSecret creates or updates the Secret holding the minted token, owned by the JWTRequest.
func (r *JWTRequestReconciler) upsertSecret(ctx context.Context, jr *v1alpha1.JWTRequest, token string) error {

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jr.Spec.SecretName,
			Namespace: jr.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		secret.Annotations["jwtmint.io/mintedAt"] = time.Now().UTC().Format(time.RFC3339)
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[SecretDataKey] = []byte(token)
		secret.Type = corev1.SecretTypeOpaque
		return controllerutil.SetControllerReference(jr, secret, r.Client.Scheme())
	})
	return err
}

// setMinted sets Ready/Minted conditions to True with the appropriate reason.
func (r *JWTRequestReconciler) setMinted(jr *v1alpha1.JWTRequest, fresh bool) {
	reason := v1alpha1.ReasonRefreshed
	if fresh {
		reason = v1alpha1.ReasonMinted
	}
	setCondition(jr, v1alpha1.ConditionReady, metav1.ConditionTrue, reason, "secret up to date")
	setCondition(jr, v1alpha1.ConditionMinted, metav1.ConditionTrue, reason, "token minted")
}

// setClaimsAccepted reports whether every spec.extraClaims entry was used. The mintResult
// enumerates rejections by reason: reserved keys (RFC 7519 registered claims that callers
// should set via dedicated spec fields) and invalid values (entries whose JSON is
// unparseable). When both reasons fire, the condition message lists each separately.
func (r *JWTRequestReconciler) setClaimsAccepted(jr *v1alpha1.JWTRequest, res mintResult) {
	reserved := res.dropped[claimDropReserved]
	invalid := res.dropped[claimDropInvalid]

	if len(reserved) == 0 && len(invalid) == 0 {
		setCondition(jr, v1alpha1.ConditionClaimsAccepted, metav1.ConditionTrue,
			v1alpha1.ReasonAllClaimsAccepted, "all extraClaims used")
		return
	}

	var parts []string
	reason := v1alpha1.ReasonReservedClaimsDropped
	if len(reserved) > 0 {
		parts = append(parts, fmt.Sprintf("reserved keys: %s (set via dedicated spec fields)",
			strings.Join(reserved, ", ")))
	}
	if len(invalid) > 0 {
		parts = append(parts, fmt.Sprintf("invalid JSON values: %s",
			strings.Join(invalid, ", ")))
		if len(reserved) == 0 {
			reason = v1alpha1.ReasonInvalidClaimValues
		}
	}
	setCondition(jr, v1alpha1.ConditionClaimsAccepted, metav1.ConditionFalse,
		reason, "ignored extraClaims — "+strings.Join(parts, "; "))
}

// setFailed sets Ready=False with the given message.
func (r *JWTRequestReconciler) setFailed(jr *v1alpha1.JWTRequest, msg string) {
	setCondition(jr, v1alpha1.ConditionReady, metav1.ConditionFalse, v1alpha1.ReasonMintFailed, msg)
	setCondition(jr, v1alpha1.ConditionMinted, metav1.ConditionFalse, v1alpha1.ReasonMintFailed, msg)
}

// updateStatus persists status changes to the API server.
func (r *JWTRequestReconciler) updateStatus(ctx context.Context, jr *v1alpha1.JWTRequest) error {
	return r.Client.Status().Update(ctx, jr)
}

// setCondition replaces or appends the named condition.
func setCondition(jr *v1alpha1.JWTRequest, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i, c := range jr.Status.Conditions {
		if c.Type != condType {
			continue
		}
		if c.Status != status {
			c.LastTransitionTime = now
		}
		c.Status = status
		c.Reason = reason
		c.Message = message
		c.ObservedGeneration = jr.Generation
		jr.Status.Conditions[i] = c
		return
	}
	jr.Status.Conditions = append(jr.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
		ObservedGeneration: jr.Generation,
	})
}

// resolveExpiration parses spec.ExpiresIn or falls back to defaultExp.
func resolveExpiration(spec string, defaultExp time.Duration) (time.Duration, error) {
	if spec == "" {
		if defaultExp <= 0 {
			defaultExp = time.Hour
		}
		return defaultExp, nil
	}
	d, err := time.ParseDuration(spec)
	if err != nil {
		return 0, fmt.Errorf("invalid expiresIn %q: %w", spec, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("expiresIn must be > 0")
	}
	return d, nil
}

// evaluateRefresh decides whether the secret needs a fresh token now and how long until
// the next refresh would be needed.
func evaluateRefresh(secret *corev1.Secret, expiration time.Duration, threshold float64) (needsRefresh bool, requeueAfter time.Duration) {
	if secret == nil {
		return true, 0
	}

	tokenBytes, ok := secret.Data[SecretDataKey]
	if !ok || len(tokenBytes) == 0 {
		return true, 0
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(string(tokenBytes), parsed); err != nil {
		return true, 0
	}

	exp, err := claims.ExpiresAt(parsed)
	if err != nil {
		return true, 0
	}

	remaining := time.Until(exp)
	cutoff := time.Duration(float64(expiration) * threshold)
	if remaining <= cutoff {
		return true, 0
	}
	return false, remaining - cutoff
}

// nextRefresh computes when to requeue after a successful mint.
func nextRefresh(expiresAt time.Time, expiration time.Duration, threshold float64) time.Duration {
	cutoff := time.Duration(float64(expiration) * threshold)
	d := time.Until(expiresAt) - cutoff
	if d < time.Second {
		return time.Second
	}
	return d
}
