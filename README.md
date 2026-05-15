# jwtsmith

A JWT toolkit for Go: a library, a daemon, a Kubernetes controller, an admission
webhook, and HTTP/gRPC middleware. Built around the `golang-jwt/jwt/v5` parser, with
context propagation, configurable clock skew, multi-key rotation, JWKS publishing,
revocation, and an opt-in OIDC discovery endpoint.

## Status

Pre-1.0. APIs may change without backward-compatibility shims. Versioned releases will
start once the surface stabilizes.

## Components

- `signing/` — `Signer` interface that mints tokens with sensible defaults (exp, iat, nbf,
  jti, iss, typ) and reserved-header protection (`alg` cannot be overridden).
- `verification/` — single-key `Verifier` and multi-key `MultiKeyVerifier` (kid-dispatched).
  Pluggable `TokenCheckFunc` chain runs after signature and registered-claims validation.
- `revocation/` — `Revoker` interface with an in-process `MemRevoker` and a `Chain`
  combinator. Plugs into the verifier via `verification.WithRevoker`.
- `refresh/` — rotates an existing token while preserving the original lifetime window.
  `MaxAge` bounds how old a token can be and still refresh; `ClaimsResolver` rewrites
  or denies claims at refresh time.
- `claims/` — typed read/write helpers for `jwt.MapClaims` and registered claim keys.
- `keys/` — keypair generation, validation, and `Keyfunc` adapters.
- `jwks/` — local `KeySet`, `JWK`/`JWKS` types, and `Remote` (cached fetch with negative
  caching and Cache-Control honoring).
- `httpserver/` — `jwtsmithd` daemon: `/sign`, `/verify`, `/refresh`,
  `/.well-known/jwks.json`, `/.well-known/openid-configuration` (opt-in),
  `/k8s/token-review` (opt-in), `/metrics`, `/healthz`. Bearer-auth or pluggable
  `Authenticator` for mutating endpoints.
- `k8s/controller/` — controller-runtime reconciler that watches `JWTRequest` resources
  and maintains a `Secret` holding a fresh token, refreshing before expiry.
- `k8s/admission/` — `ValidatingAdmissionWebhook` policy enforcing what claims a caller
  can request. Default-deny for audiences/groups/entitlements/roles/extra-claim keys;
  opt out per-list with `"*"`.
- `k8s/tokenreview/` — Kubernetes TokenReview webhook handler that validates inbound
  tokens and projects claims into `Status.User.Extra`.
- `middleware/httpauth/` and `middleware/grpcauth/` — server middlewares that enforce
  verification, plus client-side token attachers (`RoundTripper`, `UnaryClientInterceptor`,
  `StreamClientInterceptor`) backed by pluggable `TokenSource` (static, file, cached).

## Quick start (library)

```go
import (
    "context"
    "crypto/elliptic"

    "github.com/golang-jwt/jwt/v5"

    "github.com/dcadolph/jwtsmith/claims"
    "github.com/dcadolph/jwtsmith/keys"
    "github.com/dcadolph/jwtsmith/signing"
    "github.com/dcadolph/jwtsmith/verification"
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

See `examples/` for runnable end-to-end snippets per component.

Benchmarks for sign and verify across all supported algorithms live in
`signing/bench_test.go` and `verification/bench_test.go`. Run with
`go test -run=- -bench=. -benchmem ./signing ./verification`.

## Design choices

**Asymmetric only.** HMAC methods (`HS256` etc.) are rejected at signer construction.
JWTs cross trust boundaries; HMAC requires shared secrets, which is the wrong shape for
a library that publishes verification keys via JWKS. Use ES256 (default in examples),
ES384, ES512, RS256/384/512, PS256/384/512, or EdDSA.

**Context everywhere.** `Sign`, `Verify`, `Refresh`, `TokenCheckFunc`, and
`claims.CheckFunc` all take `context.Context`. Lookups (revocation, ClaimsResolver, etc.)
must honor request deadlines.

**Default leeway.** `verification.NewVerifier` applies a 30-second clock-skew leeway to
`exp`/`nbf` by default. Override with `verification.WithLeeway(0)` to disable or
`verification.WithLeeway(d)` to widen.

**Default-deny for admission.** The admission webhook's `SelfOnlyPolicy` defaults to
denying every requested audience/group/entitlement/role/extra-claim key. Use `"*"` in the
allow list to opt out (per-list, not global).

**Reserved headers.** `alg` is set by the signing library and cannot be overridden via
`WithStaticHeaders` or per-call headers — overriding it would lie about the signature
algorithm. `typ` *can* be overridden (e.g. `at+jwt` for RFC 9068 access tokens) via
`signing.WithDefaultTyp` or the per-call `headers` argument to `Sign`.

**Refresh has guardrails.** `refresh.NewRefresher` defaults to a 24h `MaxAge` (a token
older than that by `iat` cannot be refreshed). Pass `refresh.WithMaxAge(0)` to disable
or `refresh.WithMaxAge(d)` to set explicitly. `refresh.WithClaimsResolver` lets callers
rewrite or reject claims at refresh time (drop revoked groups, fail refresh for
deprovisioned users, etc.).

## Out of scope

- JWE (encrypted tokens). JWS only.
- `x5c` / `x5t` certificate chains in JWK. The `JWK` type carries `kid`, `kty`, `alg`, and
  the public-key params; cert chains belong in a separate trust path.
- RFC 7638 thumbprint helpers. Not currently provided.
- Symmetric (HMAC) signing methods.

## Operational notes

**Key rotation.** Roll forward by adding the new keypair as `Config.Method`/`PrivateKey`/
`PublicKey` and demoting the previous keypair into `Config.AdditionalKeys`. Both kids
remain in the JWKS until the previous key's tokens have all expired; restart without the
demoted entry to complete the cutover. The verifier dispatches by `kid` header.

**Revocation.** For single-replica deployments, plug `revocation.NewMemRevoker()` into
`httpserver.Config.Revoker`. For multi-replica fleets, implement `revocation.Revoker`
against your shared store (Redis, etcd, database) and front it with a MemRevoker via
`revocation.Chain(memCache, sharedStore)`. Backend errors fail verification — this is
intentional, the alternative is fail-open. `MemRevoker` does not auto-evict expired
entries; call `Cleanup()` on a ticker if revocation traffic is heavy enough to grow the
map noticeably.

**`/verify` is a query, not auth.** It returns `200` with `{valid: false}` for bad
tokens, not `401`. It exists for ad-hoc debugging and for callers without a JWT library
in their stack. **Don't put `/verify` in a hot path** — verifying locally with the JWKS
is orders of magnitude faster than a round trip per request.

**Body limits.** The daemon caps request bodies at 64 KiB (`/sign`, `/verify`, `/refresh`,
`/k8s/token-review`); the JWKS Remote caps fetched bodies at 1 MiB. Increase via the
relevant config when you have a real reason.

## Daemon (`jwtsmithd`)

```
go install github.com/dcadolph/jwtsmith/cmd/jwtsmithd@latest
```

See `cmd/jwtsmithd/` for flags. Minimum required: `--method`, `--private-key`,
`--public-key`. Enable `/k8s/token-review` with `--enable-token-review`; OIDC discovery
with `--issuer https://your-host:port`; Prometheus metrics are always on at `/metrics`.

`/metrics` and `/healthz` are unauthenticated — they assume a service-mesh-internal
trust boundary, the same posture most controllers and operators take. If you expose the
daemon to the public internet, gate those paths at the ingress.

## Controller (`jwtsmith-controller`)

```
go install github.com/dcadolph/jwtsmith/cmd/jwtsmith-controller@latest
```

Watches `JWTRequest` resources and maintains a `Secret` holding a fresh token, refreshing
before expiry. Optional admission webhook (`--enable-admission-webhook`) enforces the
`SelfOnlyPolicy`. See `deploy/` for example manifests.

## License

Apache 2.0. See `LICENSE`.
