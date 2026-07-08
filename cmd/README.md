# jwtmint commands

Three binaries live under `cmd/`:

| Binary                 | Package                     | Role                                                          |
|------------------------|-----------------------------|---------------------------------------------------------------|
| `jwtmint`              | `cmd`                       | CLI toolkit: generate keys, sign, inspect, verify, refresh, JWKS. |
| `jwtmintd`             | `cmd/jwtmintd`              | HTTP daemon exposing sign, verify, refresh, JWKS, and health. |
| `jwtmint-controller`   | `cmd/jwtmint-controller`   | Kubernetes controller reconciling `JWTRequest` resources into Secrets. |

Module path is `github.com/dcadolph/jwtmint`. Go 1.26.0.

## Build and install

```sh
# All three binaries.
go build ./cmd/...

# Just the CLI, with a version stamp.
go build -ldflags "-X github.com/dcadolph/jwtmint/cmd.Version=v0.1.0" -o jwtmint .

# Install the CLI onto your PATH.
go install github.com/dcadolph/jwtmint@latest
```

`Version` defaults to `dev` when built without the ldflag. `jwtmint --version` prints it.

## Configuration precedence

The CLI resolves settings in this order, highest first:

```
explicit flag value > environment variable > default
```

Environment variables use the `JWTMINT_` prefix. A flag name maps to an env var by
uppercasing and replacing hyphens with underscores. For example `--default-issuer`
reads `JWTMINT_DEFAULT_ISSUER`. There is no config file; configuration is flags and
env only.

## Exit codes

| Code | Name              | Meaning                                                      |
|------|-------------------|--------------------------------------------------------------|
| 0    | `ExitOK`          | Success.                                                     |
| 1    | `ExitFailure`     | Runtime failure such as a missing file or signature mismatch. |
| 2    | `ExitUsage`       | Usage error such as a bad flag combination or missing input. |
| 130  | `ExitInterrupted` | Interrupted by Ctrl+C or SIGTERM.                            |

JSON and tokens go to stdout. Status lines and errors go to stderr, so you can pipe
stdout cleanly. A token can be passed as a positional argument, via `--token`, or on
stdin for the commands that accept one.

## CLI: `jwtmint`

Short: JWT toolkit to generate keys, sign, decode, verify, refresh, and distribute via JWKS.

### `gen-key`

Generate an asymmetric key pair and write PEM files.

| Flag          | Default   | Description                                                  |
|---------------|-----------|-------------------------------------------------------------|
| `--algorithm` | `ecdsa`   | Algorithm: `ecdsa`, `rsa`, or `ed25519`.                    |
| `--curve`     | `P-256`   | ECDSA curve: `P-256`, `P-384`, or `P-521`.                  |
| `--bits`      | `2048`    | RSA key size in bits (>= 2048).                             |
| `--priv-out`  | ``        | Path to write the private key PEM. Required unless `--print`. |
| `--pub-out`   | ``        | Path to write the public key PEM. Required unless `--print`. |
| `--print`     | `false`   | Print PEM to stdout (private then public) instead of files. |

```sh
jwtmint gen-key --algorithm ecdsa --curve P-256 --priv-out es256.key --pub-out es256.pub
```

### `sign`

Sign a JWT with a private key. The signed token prints to stdout.

Claim sources merge in this order, later winning: profile flags (`--subject`,
`--issuer`, and so on), then `--claims-file`, then `--claims-json`, then `--claim`.

| Flag             | Default | Description                                                       |
|------------------|---------|------------------------------------------------------------------|
| `--method`       | `ES256` | Signing method (ES/RS/PS 256/384/512, EdDSA).                    |
| `--priv`         | ``      | Path to PEM private key. Required.                               |
| `--expires`      | `1h`    | Token lifetime, for example `30m`, `24h`.                        |
| `--claims-file`  | ``      | Path to a JSON file of claims to merge.                          |
| `--claims-json`  | ``      | JSON string of claims to merge.                                  |
| `--claim`        | ``      | Add `key=value` (repeatable). Value is a string.                |
| `--header`       | ``      | Add header `key=value` (repeatable). `alg` and `typ` reserved.  |
| `--subject`      | ``      | `sub` claim.                                                    |
| `--issuer`       | ``      | `iss` claim.                                                    |
| `--audience`     | ``      | `aud` claim, repeatable or comma-separated.                     |
| `--groups`       | ``      | Groups claim, repeatable or comma-separated.                    |
| `--roles`        | ``      | Roles claim, repeatable or comma-separated.                     |
| `--entitlements` | ``      | Entitlements claim, repeatable or comma-separated.              |
| `--permissions`  | ``      | Permissions claim, repeatable or comma-separated.               |
| `--scope`        | ``      | OAuth2 scope, joined with spaces, repeatable or comma-separated. |
| `--email`        | ``      | Email claim.                                                    |
| `--name`         | ``      | Name claim.                                                     |
| `--username`     | ``      | Username claim.                                                 |
| `--token-type`   | ``      | `token_type` claim.                                             |
| `--jti`          | ``      | Token ID. Random UUID if omitted.                               |
| `--not-before`   | ``      | `nbf` as RFC3339. Defaults to now.                              |

```sh
jwtmint sign --priv es256.key --issuer https://issuer.example \
  --subject alice --audience api --expires 15m
```

### `inspect`

Decode and print a token's headers and claims. Does not verify the signature.

| Flag       | Default | Description                                            |
|------------|---------|--------------------------------------------------------|
| `--token`  | ``      | Token to inspect. Defaults to positional arg or stdin. |
| `--pretty` | `false` | Indent the JSON output.                                |

Output is a JSON object with `header`, `claims`, and `signature`.

```sh
jwtmint inspect --pretty "$TOKEN"
cat token.txt | jwtmint inspect
```

### `verify`

Verify a signature and run optional claim checks. Exits non-zero on failure. Supply
exactly one of `--pub` or `--jwks-url`.

| Flag              | Default | Description                                                |
|-------------------|---------|------------------------------------------------------------|
| `--method`        | `ES256` | Expected signing method.                                   |
| `--pub`           | ``      | Path to PEM public key. Mutually exclusive with `--jwks-url`. |
| `--jwks-url`      | ``      | JWKS endpoint. Resolves the key by the token's `kid`.      |
| `--token`         | ``      | Token to verify. Defaults to positional arg or stdin.      |
| `--issuer`        | ``      | Allowed issuers. Token `iss` must match one.               |
| `--audience`      | ``      | Required audiences (any-of match).                         |
| `--groups`        | ``      | Required groups (any-of match).                            |
| `--roles`         | ``      | Required roles (any-of match).                             |
| `--entitlements`  | ``      | Required entitlements (any-of match).                      |
| `--require-claim` | ``      | Required claim keys (presence check).                      |
| `--print`         | `false` | Print verified claims to stdout on success.                |
| `--pretty`        | `false` | Indent the printed JSON.                                   |

Prints `ok` to stderr on success. Non-zero exit on signature mismatch or a failed
claim check.

```sh
jwtmint verify --jwks-url https://issuer.example/.well-known/jwks.json \
  --issuer https://issuer.example --audience api --print "$TOKEN"
```

### `refresh`

Refresh a token, preserving its lifetime window. The refreshed token prints to stdout.

| Flag                | Default | Description                                              |
|---------------------|---------|----------------------------------------------------------|
| `--method`          | `ES256` | Signing method.                                          |
| `--pub`             | ``      | Path to PEM public key. Required.                        |
| `--priv`            | ``      | Path to PEM private key. Required.                       |
| `--token`           | ``      | Token to refresh. Defaults to positional arg or stdin.   |
| `--default-expires` | `1h`    | Lifetime when the original has no recoverable window.    |

### `jwks`

Work with JSON Web Key Sets.

`jwks from-key` converts a PEM public key to a JWK, or a single-key JWKS with `--set`.

| Flag       | Default | Description                          |
|------------|---------|--------------------------------------|
| `--pub`    | ``      | Path to PEM public key. Required.    |
| `--kid`    | ``      | Key ID to embed in the JWK.          |
| `--set`    | `false` | Wrap output as a single-key JWKS.    |
| `--pretty` | `false` | Indent JSON output.                  |

`jwks fetch` fetches a remote JWKS over HTTPS and prints it.

| Flag       | Default | Description                       |
|------------|---------|-----------------------------------|
| `--url`    | ``      | JWKS URL to fetch. Required.      |
| `--kid`    | ``      | Filter to the JWK with this kid.  |
| `--pretty` | `false` | Indent JSON output.               |

```sh
jwtmint jwks from-key --pub es256.pub --kid key-1 --set --pretty
jwtmint jwks fetch --url https://issuer.example/.well-known/jwks.json
```

## Daemon: `jwtmintd`

Serves `/sign`, `/verify`, `/refresh`, `/.well-known/jwks.json`, and `/healthz` so
non-Go services can issue and verify tokens through one endpoint. It runs until SIGINT
or SIGTERM and shuts down gracefully.

| Flag                   | Default    | Description                                                    |
|------------------------|------------|---------------------------------------------------------------|
| `--addr`               | `:8080`    | Listen address, `host:port`.                                  |
| `--method`             | required   | Signing method (ES/RS/PS 256/384/512, EdDSA).                |
| `--priv`               | required   | Path to private key PEM.                                       |
| `--pub`                | required   | Path to public key PEM.                                        |
| `--kid`                | ``         | Key ID in JWKS and token header. Required with `--additional-key`. |
| `--additional-key`     | ``         | Verify-only key `kid=/path` for rotation overlap (repeatable). |
| `--default-issuer`     | ``         | Default `iss` when `/sign` callers omit it.                   |
| `--default-expires`    | `1h`       | Default lifetime when `expires_in` is omitted.                |
| `--auth-mode`          | `static`   | Authenticator for `/sign` and `/refresh`: `static`, `sa`, `none`. |
| `--auth-token`         | ``         | Static bearer token (`auth-mode=static`). Empty disables.     |
| `--allowed-sa`         | ``         | Allowed SA username (`auth-mode=sa`), repeatable.             |
| `--auth-audience`      | ``         | Required audience on caller SA tokens (`auth-mode=sa`), repeatable. |
| `--enable-token-review`| `false`    | Expose `/k8s/token-review` (Kubernetes TokenReview webhook).  |
| `--issuer`             | ``         | Public `scheme://host[:port]`. Exposes `/.well-known/openid-configuration`. |
| `--cert`               | ``         | TLS certificate path. Required with `--key` for HTTPS.        |
| `--key`                | ``         | TLS private key path. Required with `--cert` for HTTPS.       |
| `--log-level`          | `info`     | zap level: `debug`, `info`, `warn`, `error`.                 |
| `--read-timeout`       | `10s`      | HTTP read timeout.                                            |
| `--write-timeout`      | `10s`      | HTTP write timeout.                                           |
| `--shutdown-timeout`   | `15s`      | Graceful shutdown timeout.                                    |

All flags accept `JWTMINT_*` environment variables.

```sh
jwtmintd --method ES256 --priv es256.key --pub es256.pub --kid key-1 \
  --default-issuer https://issuer.example --auth-mode static --auth-token secret
```

## Controller: `jwtmint-controller`

Reconciles `JWTRequest` resources into Secrets. It signs with a single keypair loaded
at startup, the same model as `jwtmintd`, and re-mints tokens as their lifetime ticks
down past a refresh threshold. Runs until its context is canceled.

| Flag                              | Default                                | Description                                       |
|-----------------------------------|----------------------------------------|---------------------------------------------------|
| `--method`                        | `ES256`                                | Signing method.                                   |
| `--priv`                          | required                               | Path to PEM private key.                          |
| `--pub`                           | required                               | Path to PEM public key.                           |
| `--kid`                           | ``                                     | Key ID embedded as a token header.                |
| `--default-issuer`                | `jwtmint-controller`                   | Default `iss` claim.                              |
| `--default-expires`               | `1h`                                   | Default lifetime when `spec.expiresIn` is empty.  |
| `--metrics-addr`                  | `:8080`                                | Metrics endpoint address.                         |
| `--health-addr`                   | `:8081`                                | Health and readiness endpoint address.            |
| `--leader-elect`                  | `false`                                | Enable leader election for HA.                    |
| `--enable-admission-webhook`      | `false`                                | Serve the validating admission webhook.           |
| `--webhook-port`                  | `9443`                                 | Admission webhook server port.                    |
| `--webhook-cert-dir`              | `/tmp/k8s-webhook-server/serving-certs`| Directory holding `tls.crt` and `tls.key`.        |
| `--admission-allowed-audience`    | ``                                     | Audience a `JWTRequest` may request (repeatable). Empty allows all. |
| `--admission-allowed-entitlement` | ``                                     | Entitlement a `JWTRequest` may request (repeatable). Empty allows all. |
| `--admission-admin-user`          | ``                                     | User exempt from admission policy (repeatable).   |
| `--admission-admin-group`         | ``                                     | Group exempt from admission policy (repeatable).  |

Leader election uses the ID `jwtmint-controller-leader`.
