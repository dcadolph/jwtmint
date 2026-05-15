package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// JWTRequest declares a JWT to be minted and stored in a Secret.
//
// The reconciler creates or updates the Secret named in Spec.SecretName with the
// signed token under data key "token". When the existing token's remaining lifetime
// drops below RefreshThreshold, the reconciler re-mints it.
type JWTRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired token.
	Spec JWTRequestSpec `json:"spec,omitempty"`
	// Status reports the latest mint outcome.
	Status JWTRequestStatus `json:"status,omitempty"`
}

// JWTRequestSpec is the desired state for a JWT.
type JWTRequestSpec struct {
	// SecretName is the name of the Secret that will hold the minted token.
	// The Secret is created in the same namespace as the JWTRequest.
	SecretName string `json:"secretName"`

	// Subject sets the "sub" claim. Optional.
	Subject string `json:"subject,omitempty"`

	// Issuer overrides the controller's default issuer for this token. Optional.
	Issuer string `json:"issuer,omitempty"`

	// Audience populates the "aud" claim. Optional.
	Audience []string `json:"audience,omitempty"`

	// Groups populates the "groups" claim. Optional.
	Groups []string `json:"groups,omitempty"`

	// Roles populates the "roles" claim. Optional.
	Roles []string `json:"roles,omitempty"`

	// Entitlements populates the "entitlements" claim. Optional.
	Entitlements []string `json:"entitlements,omitempty"`

	// ExtraClaims adds arbitrary claims. Each value is preserved as raw JSON, so callers
	// can express strings, numbers, booleans, arrays, or nested objects — anything valid
	// at the JWT-claim layer. Reserved registered claims (exp, iat, nbf, jti, iss, aud,
	// sub) are ignored; set them via dedicated fields. Values that aren't valid JSON are
	// reported via the ClaimsAccepted condition rather than silently dropped.
	ExtraClaims map[string]apiextensionsv1.JSON `json:"extraClaims,omitempty"`

	// ExpiresIn is the token lifetime. Defaults to the controller's default expiration when empty.
	// Format: a Go duration string (e.g. "1h", "30m", "24h").
	ExpiresIn string `json:"expiresIn,omitempty"`

	// RefreshThreshold sets when to mint a new token: the reconciler re-mints once the
	// remaining lifetime drops below this fraction of the total lifetime. Range (0, 1].
	// Defaults to 0.25 when zero.
	RefreshThreshold *float64 `json:"refreshThreshold,omitempty"`
}

// JWTRequestStatus reports observed state.
type JWTRequestStatus struct {
	// SecretName is the Secret currently holding the minted token.
	SecretName string `json:"secretName,omitempty"`
	// LastMintedAt is when the controller most recently minted a token.
	LastMintedAt *metav1.Time `json:"lastMintedAt,omitempty"`
	// ExpiresAt is the exp claim of the most recently minted token.
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
	// JTI is the jti claim of the most recently minted token.
	JTI string `json:"jti,omitempty"`
	// ObservedGeneration is the spec generation reflected in this status.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions describe the current state of the request.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// JWTRequestList contains a list of JWTRequest.
type JWTRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []JWTRequest `json:"items"`
}

// Condition types reported on JWTRequest status.
const (
	// ConditionReady indicates the Secret is up to date with the desired JWT.
	ConditionReady = "Ready"
	// ConditionMinted indicates the most recent mint attempt succeeded.
	ConditionMinted = "Minted"
	// ConditionClaimsAccepted reports whether the spec's extraClaims were used verbatim.
	// False when the reconciler dropped or rewrote any caller-supplied claim — currently
	// the case when extraClaims contains an RFC 7519 registered claim that must be set
	// via a dedicated spec field instead.
	ConditionClaimsAccepted = "ClaimsAccepted"
)

// Condition reasons.
const (
	// ReasonMinted indicates the controller minted a fresh token.
	ReasonMinted = "Minted"
	// ReasonRefreshed indicates the controller re-minted an expiring token.
	ReasonRefreshed = "Refreshed"
	// ReasonMintFailed indicates the latest mint attempt failed.
	ReasonMintFailed = "MintFailed"
	// ReasonAllClaimsAccepted indicates every spec.extraClaims entry made it into the token.
	ReasonAllClaimsAccepted = "AllClaimsAccepted"
	// ReasonReservedClaimsDropped indicates one or more spec.extraClaims keys were ignored
	// because they are RFC 7519 registered claims that must be set via dedicated spec fields.
	// Also used when a mix of reserved keys and invalid JSON values were rejected together.
	ReasonReservedClaimsDropped = "ReservedClaimsDropped"
	// ReasonInvalidClaimValues indicates one or more spec.extraClaims values were not valid
	// JSON and were therefore omitted from the minted token.
	ReasonInvalidClaimValues = "InvalidClaimValues"
)
