// Package k8sauth provides an httpserver.Authenticator that validates the caller's
// Kubernetes ServiceAccount token by submitting a TokenReview to the apiserver.
//
// This is the k8s-native alternative to a static bearer token: pods authenticate to
// jwtmintd using their projected SA token, and jwtmintd verifies it against the
// apiserver before allowing /sign or /refresh.
package k8sauth

import (
	"fmt"
	"net/http"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/dcadolph/jwtmint/httpserver"
	"github.com/dcadolph/jwtmint/pkgerr"
)

// SAAuthenticator validates a request's bearer token by submitting it to the apiserver
// as a TokenReview, optionally restricting acceptance to an allow-list of ServiceAccount
// usernames (e.g. "system:serviceaccount:default:my-app").
type SAAuthenticator struct {
	client    kubernetes.Interface
	allowed   map[string]struct{}
	audiences []string
}

// Opt configures an SAAuthenticator.
type Opt func(*SAAuthenticator)

// WithAllowedSAs restricts acceptance to the given ServiceAccount usernames.
//
// Format: "system:serviceaccount:<namespace>:<name>". Empty allow-list accepts any
// authenticated SA token.
func WithAllowedSAs(usernames ...string) Opt {
	return func(a *SAAuthenticator) {
		if a.allowed == nil {
			a.allowed = make(map[string]struct{}, len(usernames))
		}
		for _, u := range usernames {
			if u != "" {
				a.allowed[u] = struct{}{}
			}
		}
	}
}

// WithAudiences asks the apiserver to validate the token only when its audience binding
// includes at least one of the given audiences. Use to scope SA tokens to jwtmintd.
func WithAudiences(audiences ...string) Opt {
	return func(a *SAAuthenticator) {
		a.audiences = append(a.audiences, audiences...)
	}
}

// New returns an SAAuthenticator using the given Kubernetes client.
//
// Use NewInCluster when running in a pod with a mounted ServiceAccount.
func New(client kubernetes.Interface, opts ...Opt) (*SAAuthenticator, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: kubernetes client required", pkgerr.ErrInvalidValue)
	}
	a := &SAAuthenticator{client: client}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// NewInCluster builds an SAAuthenticator using the in-cluster kubeconfig.
func NewInCluster(opts ...Opt) (*SAAuthenticator, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: in-cluster config: %w", pkgerr.ErrInvalidValue, err)
	}
	cli, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: kubernetes client: %w", pkgerr.ErrInvalidValue, err)
	}
	return New(cli, opts...)
}

// Authenticate implements httpserver.Authenticator.
//
// Extracts the bearer token from the Authorization header and submits it to the
// apiserver via TokenReview. Returns a non-nil error to reject the request.
func (a *SAAuthenticator) Authenticate(r *http.Request) error {

	authz := r.Header.Get("Authorization")
	if authz == "" {
		return fmt.Errorf("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		return fmt.Errorf("Authorization is not a Bearer token")
	}
	token := strings.TrimSpace(strings.TrimPrefix(authz, prefix))
	if token == "" {
		return fmt.Errorf("empty bearer token")
	}

	review := &authnv1.TokenReview{
		ObjectMeta: metav1.ObjectMeta{},
		Spec: authnv1.TokenReviewSpec{
			Token:     token,
			Audiences: a.audiences,
		},
	}

	resp, err := a.client.AuthenticationV1().TokenReviews().Create(r.Context(), review, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("token review failed: %w", err)
	}
	if !resp.Status.Authenticated {
		if resp.Status.Error != "" {
			return fmt.Errorf("apiserver rejected token: %s", resp.Status.Error)
		}
		return fmt.Errorf("apiserver did not authenticate token")
	}

	if len(a.allowed) > 0 {
		if _, ok := a.allowed[resp.Status.User.Username]; !ok {
			return fmt.Errorf("ServiceAccount %q not in allow-list", resp.Status.User.Username)
		}
	}
	return nil
}

// Compile-time assertion that SAAuthenticator satisfies httpserver.Authenticator.
var _ httpserver.Authenticator = (*SAAuthenticator)(nil)
