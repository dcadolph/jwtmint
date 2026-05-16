# Demo plan

Reference for when the project is ready for pro-grade hero videos (likely after rename
and 1.0). This document specifies *what* to record so the actual recording session is
mechanical — set up, capture, edit, ship.

## Recording stack

**Tool:** ScreenStudio (Mac) or Descript. Both produce the smooth-cursor, animated-zoom,
clean-typography look common to Linear, Vercel, and Tailscale launch videos. ScreenStudio
is cheaper and simpler; Descript adds editing-by-transcript and is the right call if any
voice-over is involved.

**Resolution:** 1920×1080 minimum, 60fps. 4K source if uploading to a marketing site.

**Terminal:** Ghostty or iTerm2 with a font ≥18pt. Avoid system shell themes that look
generic — use Catppuccin/Tokyo Night/something distinctive but readable.

**Background:** Solid color or subtle gradient. No desktop clutter, no menubar, no
notifications. Use a dedicated user account or Focus mode to suppress Slack/Mail popups.

**Cursor:** ScreenStudio's smooth cursor is non-negotiable — it's what makes recordings
look produced rather than amateur.

## Demo lineup

Each demo is paced for ~60–90 seconds. Anything longer loses the audience; anything
shorter doesn't show enough.

### 1. Library quickstart (the elevator pitch)

**Goal:** "I can mint, verify, refresh, and revoke a JWT with a few lines of Go."

**Script:**
1. Open `examples/sign-verify/main.go` in editor. Hold for 2 seconds.
2. Highlight the four key steps (signer, verifier, refresher, revoker) — use editor
   highlights or post-production callouts.
3. Cut to terminal. Run `go run ./examples/sign-verify`.
4. Show output: minted, verified, refreshed, revoked rejected.
5. Hold the final frame with a one-line caption: "All asymmetric. All in process."

**Length:** 60 seconds.

### 2. Daemon (jwtmintd)

**Goal:** "Same primitives, exposed as HTTP for any language."

**Script:**
1. Cold start: `jwtmintd --method ES256 --private-key priv.pem --public-key pub.pem &`.
   Show the startup log (jwtmintd listening on :8080).
2. `curl /healthz` → 200.
3. `curl /.well-known/jwks.json | jq` → show the published key.
4. `curl -X POST /sign -d '{"claims": {"sub": "u1"}}'` → token returned.
5. `curl -X POST /verify -d '{"token": "<paste>"}'` → `{"valid": true}`.
6. `curl /metrics | grep jwtmint_http` → show the Prometheus counters incrementing.
7. Hold final frame: "Sign, verify, refresh, JWKS, OIDC discovery, metrics."

**Length:** 90 seconds.

### 3. Kubernetes controller

**Goal:** "Declare a JWT in YAML; get a Secret you can mount."

**Pre-record setup (off-screen):** kind cluster, controller deployed, CRD applied. Don't
record the bootstrap — viewers don't care.

**Script:**
1. `cat jwtrequest.yaml` — show a 10-line manifest.
2. `kubectl apply -f jwtrequest.yaml`.
3. `kubectl get jwtrequest -w` — watch Status.Conditions go to Ready=True. Speed up the
   wait in post (2x).
4. `kubectl get secret my-token-secret -o jsonpath='{.data.token}' | base64 -d` → show
   a real JWT.
5. Time-skip to refresh: edit the JWTRequest with a shorter ExpiresIn, watch the Secret
   rotate. Speed up in post.
6. Hold final frame: "Declarative JWTs. Controller refreshes before expiry."

**Length:** 90 seconds. (60 if the time-skip is aggressive enough.)

### 4. Admission webhook

**Goal:** "The controller refuses to mint tokens callers shouldn't have."

**Pre-record setup:** Cluster with cert-manager, webhook deployed, two service accounts
(`alice` with `dev` group; `bob` with no groups).

**Script:**
1. `cat alice-request.yaml` — JWTRequest asking for `groups: [dev]`. Submit as alice.
   `kubectl apply` succeeds.
2. `cat bob-request.yaml` — same shape. Submit as bob.
   `kubectl apply` denied: `admission webhook denied the request: requester not in
   group "dev"`.
3. Hold final frame: "SelfOnlyPolicy: requesters can only mint what they themselves have."

**Length:** 60 seconds.

## Production notes

- All four demos should share visual identity: same terminal theme, same font, same
  intro/outro card.
- Caption every command — viewers without audio should understand the flow.
- Avoid voice-over unless willing to commit to it across all four. Mixed audio/silent is
  jarring.
- Export both MP4 (landing page, social) and animated WebP (README inline). GIF is
  acceptable but heavier.
- Final files belong in `docs/demos/` or hosted (GitHub Releases, Vercel, S3) — don't
  commit large binaries to main.

## Stopgap

Until the pro-grade recording session happens, the README's quickstart code block plus
the runnable `examples/sign-verify` demo are the closest equivalent. They cover demo #1
in static form.
