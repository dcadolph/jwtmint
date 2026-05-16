// jwtmint-controller is the Kubernetes controller that reconciles JWTRequest resources
// into Secrets holding freshly minted JWTs.
//
// The controller signs tokens with a single keypair loaded at startup (same model as
// jwtmintd) and re-mints them as their lifetime ticks down past a configurable
// refresh threshold. A workload pod mounts the Secret at a known path and uses the
// JWT to authenticate to other services. Verifiers either import jwtmint's middleware
// (httpauth/grpcauth) or point the kube-apiserver at jwtmintd's TokenReview webhook.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	zapr "sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/dcadolph/jwtmint/k8s/admission"
	v1alpha1 "github.com/dcadolph/jwtmint/k8s/api/v1alpha1"
	"github.com/dcadolph/jwtmint/k8s/controller"
	"github.com/dcadolph/jwtmint/keys"
	"github.com/dcadolph/jwtmint/signing"
)

// stringSlice is a flag.Value for repeatable string flags.
type stringSlice []string

// String renders the captured values comma-separated.
func (s *stringSlice) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

// Set appends one value.
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// scheme registers the API types this controller understands.
var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
}

// main parses flags, builds the manager, registers the reconciler, and runs it.
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "jwtmint-controller: %s\n", err)
		os.Exit(1)
	}
}

// run wires the controller and runs it until the parent context is canceled.
func run() error {

	var (
		method            string
		privPath          string
		pubPath           string
		kid               string
		issuer            string
		defaultExpiration time.Duration
		metricsAddr       string
		probeAddr         string
		leaderElection    bool

		enableWebhook        bool
		webhookPort          int
		webhookCertDir       string
		allowedAudiences     stringSlice
		allowedEntitlements  stringSlice
		adminUsers           stringSlice
		adminGroups          stringSlice
	)

	fs := flag.CommandLine
	fs.StringVar(&method, "method", "ES256", "Signing method (ES256, RS256, EdDSA, ...).")
	fs.StringVar(&privPath, "priv", "", "Path to PEM private key. Required.")
	fs.StringVar(&pubPath, "pub", "", "Path to PEM public key. Required.")
	fs.StringVar(&kid, "kid", "", "Key ID embedded as token header.")
	fs.StringVar(&issuer, "default-issuer", "jwtmint-controller", "Default iss claim.")
	fs.DurationVar(&defaultExpiration, "default-expires", time.Hour, "Default token lifetime when JWTRequest.spec.expiresIn is empty.")
	fs.StringVar(&metricsAddr, "metrics-addr", ":8080", "Address for the metrics endpoint.")
	fs.StringVar(&probeAddr, "health-addr", ":8081", "Address for the health/readiness endpoint.")
	fs.BoolVar(&leaderElection, "leader-elect", false, "Enable leader election for HA deployments.")
	fs.BoolVar(&enableWebhook, "enable-admission-webhook", false, "Serve the validating admission webhook for JWTRequest.")
	fs.IntVar(&webhookPort, "webhook-port", 9443, "Port for the admission webhook server.")
	fs.StringVar(&webhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs", "Directory containing tls.crt and tls.key for the webhook server.")
	fs.Var(&allowedAudiences, "admission-allowed-audience", "Audience JWTRequests may request. Repeatable. Empty allows all.")
	fs.Var(&allowedEntitlements, "admission-allowed-entitlement", "Entitlement JWTRequests may request. Repeatable. Empty allows all.")
	fs.Var(&adminUsers, "admission-admin-user", "User exempt from admission policy. Repeatable.")
	fs.Var(&adminGroups, "admission-admin-group", "Group whose members are exempt from admission policy. Repeatable.")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	if privPath == "" || pubPath == "" {
		return fmt.Errorf("--priv and --pub are required")
	}

	zapCfg := zap.NewProductionConfig()
	zapCfg.OutputPaths = []string{"stderr"}
	zapCfg.ErrorOutputPaths = []string{"stderr"}
	zapCfg.EncoderConfig.TimeKey = "ts"
	zapCfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	zapLog, err := zapCfg.Build()
	if err != nil {
		return err
	}
	defer func() { _ = zapLog.Sync() }()

	ctrl.SetLogger(zapr.New(zapr.UseDevMode(false)))

	signMethod, err := signing.SigningMethod(method)
	if err != nil {
		return err
	}
	priv, err := loadPrivate(method, privPath)
	if err != nil {
		return err
	}

	signerOpts := []signing.Opt{
		signing.WithDefaultIssuer(issuer),
		signing.WithDefaultExpiration(defaultExpiration),
	}
	if kid != "" {
		signerOpts = append(signerOpts, signing.WithStaticHeaders(map[string]any{"kid": kid}))
	}
	signer, err := signing.NewSigner(signMethod, priv, signerOpts...)
	if err != nil {
		return err
	}

	mgrOpts := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElection,
		LeaderElectionID:       "jwtmint-controller-leader",
		Controller:             ctrlconfig.Controller{},
	}
	if enableWebhook {
		mgrOpts.WebhookServer = webhook.NewServer(webhook.Options{
			Port:    webhookPort,
			CertDir: webhookCertDir,
		})
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOpts)
	if err != nil {
		return fmt.Errorf("creating manager: %w", err)
	}

	if enableWebhook {
		policy := &admission.SelfOnlyPolicy{
			AllowedAudiences:    allowedAudiences,
			AllowedEntitlements: allowedEntitlements,
			AdminUsers:          adminUsers,
			AdminGroups:         adminGroups,
		}
		mgr.GetWebhookServer().Register(admission.PathValidate, admission.Handler(policy))
		zapLog.Info("admission webhook enabled",
			zap.String("path", admission.PathValidate),
			zap.Int("port", webhookPort),
			zap.String("cert_dir", webhookCertDir),
		)
	}

	if err := (&controller.JWTRequestReconciler{
		Client:            mgr.GetClient(),
		Signer:            signer,
		DefaultExpiration: defaultExpiration,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("registering reconciler: %w", err)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("readyz check: %w", err)
	}

	zapLog.Info("jwtmint-controller starting",
		zap.String("alg", signMethod.Alg()),
		zap.String("kid", kid),
		zap.String("issuer", issuer),
		zap.String("metrics", metricsAddr),
		zap.String("health", probeAddr),
		zap.Bool("leader_elect", leaderElection),
	)
	return mgr.Start(ctrl.SetupSignalHandler())
}

// loadPrivate parses the private key PEM into the right Go type for the given method.
func loadPrivate(method, path string) (any, error) {
	pemBytes, err := keys.ReadPEMFile(path)
	if err != nil {
		return nil, err
	}
	switch method {
	case "ES256", "ES384", "ES512":
		return keys.LoadECDSAPrivateFromPEM(pemBytes)
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return keys.LoadRSAPrivateFromPEM(pemBytes)
	case "EdDSA":
		return keys.LoadEd25519PrivateFromPEM(pemBytes)
	default:
		return nil, fmt.Errorf("unsupported method %q", method)
	}
}

// _ keeps the standard library context import referenced once we add cancellation hooks.
var _ context.Context = context.Background()
