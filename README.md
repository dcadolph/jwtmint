# jwtmint

A JWT library for Go with a daemon, a Kubernetes controller, an admission webhook,
and HTTP/gRPC middleware. Wraps `golang-jwt/jwt/v5`. Adds context propagation,
configurable clock skew, multi-key rotation, JWKS publishing, revocation, and an
opt-in OIDC discovery endpoint.

## Status

Pre-1.0. APIs may change without backward-compatibility shims. Versioned releases
will start once the surface stabilizes.

## Quick start

```go
import (
    "context"
    "crypto/elliptic"

    "github.com/golang-jwt/jwt/v5"

    "github.com/dcadolph/jwtmint/claims"
    "github.com/dcadolph/jwtmint/keys"
    "github.com/dcadolph/jwtmint/signing"
    "github.com/dcadolph/jwtmint/verification"
)

priv, pub, _ := keys.GenerateECDSA(elliptic.P256())

signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv,
    signing.WithDefaultIssuer("my-service"),
)

token, _, _ := signer.Sign(context.Background(),
    jwt.MapClaims{claims.KeySubject: "user-1"}, nil)

verifier, _ := verification.NewVerifier(jwt.SigningMethodES256, pub,
    verification.WithStaticChecks(
        verification.CheckClaims(claims.CheckIssuer("my-service")),
    ),
)

if _, err := verifier.Verify(context.Background(), token); err != nil {
    // reject
}
```

Runnable per-component snippets live under `examples/`. Sign and verify benchmarks
across every supported algorithm sit beside the code they exercise. Run them with
`go test -run=- -bench=. -benchmem ./signing ./verification`.

## Architecture

Signing mints tokens with defaults for exp, iat, nbf, jti, iss, and typ, and rejects
`alg` overrides. Verification supports single-key and multi-key (kid-dispatched)
modes, with a `TokenCheckFunc` chain that runs after signature and registered-claims
validation. Revocation plugs into the verifier through a `Revoker` interface; an
in-process implementation and a chain combinator ship in the box. Refresh rotates a
token while preserving its lifetime window, with `MaxAge` bounding how old a token
can be and `ClaimsResolver` rewriting or denying claims at refresh time.

Typed claim helpers cover the registered claim keys. Keypair generation, validation,
and `Keyfunc` adapters are first-class. JWKS support includes a local key set, the
`JWK` and `JWKS` types, and a cached `Remote` fetcher with negative caching that
honors Cache-Control.

The `jwtmintd` daemon exposes `/sign`, `/verify`, `/refresh`,
`/.well-known/jwks.json`, `/.well-known/openid-configuration` (opt-in),
`/k8s/token-review` (opt-in), `/metrics`, and `/healthz`. Mutating endpoints take
bearer auth or a custom `Authenticator`.

Kubernetes integration covers a controller-runtime reconciler that watches
`JWTRequest` resources and maintains a `Secret` holding a fresh token, a
`ValidatingAdmissionWebhook` policy that enforces what claims a caller can request,
and a TokenReview webhook handler that validates inbound tokens and projects claims
into `Status.User.Extra`.

HTTP and gRPC server middlewares enforce verification. Client-side token attachers
(`RoundTripper`, `UnaryClientInterceptor`, `StreamClientInterceptor`) are backed by
a `TokenSource` with static, file, and cached variants.

## Design choices

### Asymmetric only

HMAC methods (`HS256` and so on) are rejected at signer construction. JWTs cross
trust boundaries, and HMAC requires shared secrets, which is the wrong shape for
a library that publishes verification keys via JWKS. Use ES256 (default in
examples), ES384, ES512, RS256/384/512, PS256/384/512, or EdDSA.

### Context everywhere

`Sign`, `Verify`, `Refresh`, `TokenCheckFunc`, and `claims.CheckFunc` all take
`context.Context`. Lookups for revocation, claims resolution, and similar checks
honor request deadlines.

### Default leeway

`verification.NewVerifier` applies a 30 second clock-skew leeway to `exp` and
`nbf` by default. Override with `verification.WithLeeway(0)` to disable, or
`verification.WithLeeway(d)` to widen.

### Default-deny admission

The admission webhook's `SelfOnlyPolicy` denies every requested audience, group,
entitlement, role, and extra-claim key by default. Use `"*"` in the allow list to
opt out, per list, not global.

### Reserved headers

`alg` is set by the signing library and cannot be overridden via
`WithStaticHeaders` or per-call headers. Overriding it would lie about the
signature algorithm. `typ` can be overridden, for example `at+jwt` for RFC 9068
access tokens, via `signing.WithDefaultTyp` or the per-call `headers` argument to
`Sign`.

### Refresh constraints

`refresh.NewRefresher` defaults to a 24h `MaxAge`. A token older than that by
`iat` cannot be refreshed. Pass `refresh.WithMaxAge(0)` to disable, or
`refresh.WithMaxAge(d)` to set explicitly. `refresh.WithClaimsResolver` lets
callers rewrite or reject claims at refresh time, for example dropping revoked
groups or failing refresh for deprovisioned users.

## Out of scope

- JWE (encrypted tokens). JWS only.
- `x5c` and `x5t` certificate chains in JWK. The `JWK` type carries `kid`, `kty`,
  `alg`, and the public-key params. Cert chains belong in a separate trust path.
- RFC 7638 thumbprint helpers.
- Symmetric (HMAC) signing methods.

## Operational notes

### Key rotation

Roll forward by adding the new keypair as `Config.Method`, `PrivateKey`, and
`PublicKey`. Demote the previous keypair into `Config.AdditionalKeys`. Both kids
remain in the JWKS until the previous key's tokens have expired. Restart without
the demoted entry to finish the cutover. The verifier dispatches by `kid` header.

### Revocation

For single-replica deployments, plug `revocation.NewMemRevoker()` into
`httpserver.Config.Revoker`. For multi-replica fleets, implement
`revocation.Revoker` against a shared store such as Redis, etcd, or a database,
and front it with a `MemRevoker` via `revocation.Chain(memCache, sharedStore)`.
Backend errors fail verification. This is intentional. The alternative is
fail-open. `MemRevoker` does not auto-evict expired entries. Call `Cleanup()` on
a ticker if revocation traffic is heavy enough to grow the map noticeably.

### /verify is a query, not auth

It returns `200` with `{valid: false}` for bad tokens, not `401`. It exists for
ad-hoc debugging and for callers without a JWT library in their stack. Do not put
`/verify` in a hot path. Verifying locally with the JWKS is orders of magnitude
faster than a round trip per request.

### Body limits

The daemon caps request bodies at 64 KiB on `/sign`, `/verify`, `/refresh`, and
`/k8s/token-review`. The JWKS `Remote` caps fetched bodies at 1 MiB. Raise these
via the relevant config when needed.

## Daemon (jwtmintd)

```
go install github.com/dcadolph/jwtmint/cmd/jwtmintd@latest
```

Minimum required flags: `--method`, `--private-key`, `--public-key`. Enable
`/k8s/token-review` with `--enable-token-review`. Enable OIDC discovery with
`--issuer https://your-host:port`. Prometheus metrics are always on at `/metrics`.

`/metrics` and `/healthz` are unauthenticated. They assume a service-mesh
internal trust boundary, the same posture most controllers and operators take.
If you expose the daemon to the public internet, gate those paths at the ingress.

## Controller (jwtmint-controller)

```
go install github.com/dcadolph/jwtmint/cmd/jwtmint-controller@latest
```

Watches `JWTRequest` resources and maintains a `Secret` holding a fresh token,
refreshing before expiry. Optional admission webhook
(`--enable-admission-webhook`) enforces the `SelfOnlyPolicy`. See `deploy/` for
example manifests.

## License

Apache 2.0. See `LICENSE`.
