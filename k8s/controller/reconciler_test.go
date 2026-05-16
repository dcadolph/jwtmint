package controller

import (
	"context"
	"crypto/elliptic"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/dcadolph/jwtmint/claims"
	v1alpha1 "github.com/dcadolph/jwtmint/k8s/api/v1alpha1"
	"github.com/dcadolph/jwtmint/keys"
	"github.com/dcadolph/jwtmint/signing"
)

// newReconciler builds a reconciler with a fake client and a real ECDSA signer.
func newReconciler(t *testing.T, initial ...runtime.Object) *JWTRequestReconciler {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add client scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1alpha1 scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}

	priv, _, err := keys.GenerateECDSA(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}
	signer, err := signing.NewSigner(jwt.SigningMethodES256, priv, signing.WithDefaultIssuer("ctlr"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	objs := make([]runtime.Object, 0, len(initial))
	objs = append(objs, initial...)

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.JWTRequest{}).
		WithRuntimeObjects(objs...).
		Build()

	return &JWTRequestReconciler{
		Client:            cli,
		Signer:            signer,
		DefaultExpiration: time.Hour,
	}
}

// TestReconcileMintsSecret confirms a fresh JWTRequest produces a Secret with a token.
func TestReconcileMintsSecret(t *testing.T) {
	t.Parallel()

	jr := &v1alpha1.JWTRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "request-1", Namespace: "default"},
		Spec: v1alpha1.JWTRequestSpec{
			SecretName:   "tok-1",
			Subject:      "user-1",
			Audience:     []string{"api"},
			Groups:       []string{"admins"},
			Entitlements: []string{"billing.read"},
			ExpiresIn:    "30m",
		},
	}

	r := newReconciler(t, jr)
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "request-1"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("expected RequeueAfter > 0, got %v", res.RequeueAfter)
	}

	var secret corev1.Secret
	if err := r.Client.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "tok-1"}, &secret); err != nil {
		t.Fatalf("get Secret: %v", err)
	}
	tokenBytes := secret.Data[SecretDataKey]
	if len(tokenBytes) == 0 {
		t.Fatal("Secret has no token data")
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(string(tokenBytes), parsed); err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	if sub, _ := claims.Subject(parsed); sub != "user-1" {
		t.Errorf("subject: want user-1 got %q", sub)
	}
	got, _ := claims.Audience(parsed)
	if len(got) != 1 || got[0] != "api" {
		t.Errorf("audience: want [api] got %v", got)
	}
	g, _ := claims.Groups(parsed)
	if len(g) != 1 || g[0] != "admins" {
		t.Errorf("groups: want [admins] got %v", g)
	}
	e, _ := claims.Entitlements(parsed)
	if len(e) != 1 || e[0] != "billing.read" {
		t.Errorf("entitlements: want [billing.read] got %v", e)
	}

	// Status should be updated.
	var refreshed v1alpha1.JWTRequest
	if err := r.Client.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "request-1"}, &refreshed); err != nil {
		t.Fatalf("get JWTRequest: %v", err)
	}
	if refreshed.Status.JTI == "" {
		t.Error("Status.JTI not set")
	}
	if refreshed.Status.LastMintedAt == nil {
		t.Error("Status.LastMintedAt not set")
	}
}

// TestReconcileSkipsFreshToken does not re-mint when the existing token has plenty of lifetime.
func TestReconcileSkipsFreshToken(t *testing.T) {
	t.Parallel()

	jr := &v1alpha1.JWTRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "request-1", Namespace: "default", UID: "u1"},
		Spec:       v1alpha1.JWTRequestSpec{SecretName: "tok-1", Subject: "u1", ExpiresIn: "1h"},
	}
	r := newReconciler(t, jr)

	// First reconcile mints the secret.
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "request-1"}}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	var firstSecret corev1.Secret
	if err := r.Client.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "tok-1"}, &firstSecret); err != nil {
		t.Fatalf("get first secret: %v", err)
	}
	firstToken := string(firstSecret.Data[SecretDataKey])

	// Second reconcile shortly after should not mint a new token.
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "request-1"}}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	var secondSecret corev1.Secret
	if err := r.Client.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "tok-1"}, &secondSecret); err != nil {
		t.Fatalf("get second secret: %v", err)
	}
	if got := string(secondSecret.Data[SecretDataKey]); got != firstToken {
		t.Errorf("unexpected re-mint:\nfirst: %s\nsecond:%s", firstToken[:30], got[:30])
	}
}

// TestReconcileExtraClaimsRichTypes confirms map[string]apiextensionsv1.JSON values
// flow into the minted token as their decoded JSON shapes (string, number, bool, nested
// object, array) and that a reserved-claim key supplied via extraClaims is dropped and
// surfaced via the ClaimsAccepted condition.
func TestReconcileExtraClaimsRichTypes(t *testing.T) {
	t.Parallel()

	jr := &v1alpha1.JWTRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "rich", Namespace: "default"},
		Spec: v1alpha1.JWTRequestSpec{
			SecretName: "rich-tok",
			Subject:    "u1",
			ExpiresIn:  "30m",
			ExtraClaims: map[string]apiextensionsv1.JSON{
				"tenant":     {Raw: []byte(`"acme"`)},
				"tier":       {Raw: []byte(`3`)},
				"beta":       {Raw: []byte(`true`)},
				"flags":      {Raw: []byte(`["a","b"]`)},
				"quota":      {Raw: []byte(`{"rps":100}`)},
				claims.KeyID: {Raw: []byte(`"caller-supplied"`)}, // reserved, must drop
			},
		},
	}

	r := newReconciler(t, jr)
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "rich"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var secret corev1.Secret
	if err := r.Client.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "rich-tok"}, &secret); err != nil {
		t.Fatalf("get Secret: %v", err)
	}
	parsed := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(string(secret.Data[SecretDataKey]), parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got := parsed["tenant"]; got != "acme" {
		t.Errorf("tenant: want acme got %v (%T)", got, got)
	}
	if got, _ := parsed["tier"].(float64); got != 3 {
		t.Errorf("tier: want 3 got %v", parsed["tier"])
	}
	if got, _ := parsed["beta"].(bool); !got {
		t.Errorf("beta: want true got %v", parsed["beta"])
	}
	if got, ok := parsed["flags"].([]any); !ok || len(got) != 2 {
		t.Errorf("flags: want array of 2 got %v", parsed["flags"])
	}
	if quota, ok := parsed["quota"].(map[string]any); !ok || quota["rps"] != float64(100) {
		t.Errorf("quota: want {rps:100} got %v", parsed["quota"])
	}
	if jti, _ := claims.JTI(parsed); jti == "caller-supplied" {
		t.Error("reserved jti from extraClaims leaked into token")
	}

	var refreshed v1alpha1.JWTRequest
	if err := r.Client.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "rich"}, &refreshed); err != nil {
		t.Fatalf("get JWTRequest: %v", err)
	}

	var accepted *metav1.Condition
	for i := range refreshed.Status.Conditions {
		if refreshed.Status.Conditions[i].Type == v1alpha1.ConditionClaimsAccepted {
			accepted = &refreshed.Status.Conditions[i]
			break
		}
	}
	if accepted == nil {
		t.Fatal("ClaimsAccepted condition not present")
	}
	if accepted.Status != metav1.ConditionFalse {
		t.Errorf("ClaimsAccepted status: want False got %s", accepted.Status)
	}
	if !strings.Contains(accepted.Message, "jti") {
		t.Errorf("ClaimsAccepted message missing %q: %q", "jti", accepted.Message)
	}
}

// TestMintInvalidExtraClaimsValue exercises the invalid-JSON path in mint directly.
// We bypass Reconcile (and its client roundtrip) because the apiserver and the fake
// client both reject invalid JSON in apiextensionsv1.JSON during their own marshal step;
// the defensive code in mint exists for out-of-band paths (etcd edits, migrations from
// looser CRDs) where invalid JSON could conceivably reach the reconciler.
func TestMintInvalidExtraClaimsValue(t *testing.T) {
	t.Parallel()

	r := newReconciler(t)
	jr := &v1alpha1.JWTRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "bogus", Namespace: "default"},
		Spec: v1alpha1.JWTRequestSpec{
			SecretName: "bogus-tok",
			Subject:    "u1",
			ExtraClaims: map[string]apiextensionsv1.JSON{
				"good": {Raw: []byte(`"yes"`)},
				"bad":  {Raw: []byte(`{not json`)},
			},
		},
	}

	signed, _, res, err := r.mint(context.Background(), jr, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if signed == "" {
		t.Fatal("mint returned empty token")
	}
	invalid := res.dropped[claimDropInvalid]
	if len(invalid) != 1 || invalid[0] != "bad" {
		t.Errorf("dropped invalid: want [bad] got %v", invalid)
	}
}

// TestReconcileRejectsBadSpec sets a Failed condition when SecretName is empty.
func TestReconcileRejectsBadSpec(t *testing.T) {
	t.Parallel()

	jr := &v1alpha1.JWTRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "default"},
		Spec:       v1alpha1.JWTRequestSpec{},
	}
	r := newReconciler(t, jr)
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "bad"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var refreshed v1alpha1.JWTRequest
	if err := r.Client.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "bad"}, &refreshed); err != nil {
		t.Fatalf("get: %v", err)
	}

	var ready *metav1.Condition
	for i := range refreshed.Status.Conditions {
		if refreshed.Status.Conditions[i].Type == v1alpha1.ConditionReady {
			ready = &refreshed.Status.Conditions[i]
			break
		}
	}
	if ready == nil {
		t.Fatal("Ready condition not present")
	}
	if ready.Status != metav1.ConditionFalse {
		t.Errorf("Ready: want False got %s", ready.Status)
	}
}
