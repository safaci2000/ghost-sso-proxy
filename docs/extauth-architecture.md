# Ghost SSO: ExtAuth Architecture and Implementation Notes

This document describes the current (working) architecture of `ghost-sso-proxy`, the problems
encountered along the way, and the design decisions that resolved them. The other docs in this
directory (`architecture.md`, `envoy-wiring.md`, `kubernetes-deployment.md`) describe the original
ExtProc design, which was retired. Treat this document as the authoritative reference.

---

## Background: why ExtProc was replaced

The original design used Envoy's External Processor (`EnvoyExtensionPolicy` → `extProc`). In
principle, ExtProc is powerful: Envoy streams request and response headers to the sidecar, and the
sidecar can mutate them or issue an `ImmediateResponse`. In practice, the Envoy Gateway controller
accepted the `EnvoyExtensionPolicy` with `status: Accepted: True`, but never programmed an
`ext_proc` filter into the Envoy data plane. A live `config_dump` of the Envoy proxy pod confirmed
zero `ext_proc` filter entries. The root cause is suspected to be a translation bug in the
`EnvoyExtensionPolicy → xDS` path in the version of Envoy Gateway in use.

The replacement is External Authorization (`SecurityPolicy` → `extAuth`). ExtAuth uses a much
simpler protocol: a single unary `Check` RPC per request (no bidirectional streaming), and the
`SecurityPolicy` code path in Envoy Gateway is far more battle-tested because it is the same path
used for the OIDC filter.

---

## Current architecture

```
Browser
  │
  ▼
Envoy Gateway (http-gateway)
  │  HTTPS listener — two filters in this order after the fix:
  │    [0] envoy.filters.http.oauth2      ← decrypts AccessToken-* cookie,
  │                                          injects Authorization: Bearer <jwt>
  │    [1] envoy.filters.http.ext_authz   ← calls ghost-auth-shim (ExtAuth)
  │    [2] envoy.filters.http.router
  │
  ├─── SecurityPolicy (ghost-oidc)
  │      OIDC: Authentik provider, forwardAccessToken: true
  │      extAuth: ghost-auth-shim:8080 (gRPC)
  │
  ▼
ghost-auth-shim (ghost-sso-proxy, this repo)
  │  implements envoy.service.auth.v3.Authorization
  │
  ├── Fast path: ghost-admin-api-session cookie already present
  │     → OkResponse (strip Authorization header so Bearer never reaches Ghost)
  │
  └── Slow path: no session cookie
        1. Extract Authorization: Bearer <access_token> from request headers
        2. Call OIDC userinfo endpoint → resolve email
        3. SELECT users WHERE email = ? → confirm active staff member
        4. SELECT sessions WHERE user_id = ? → reuse existing row (refresh session_data)
           OR INSERT new session row
        5. Sign cookie: s:<session_id>.<base64(HMAC-SHA256(session_id, admin_session_secret))>
        6. DeniedResponse 302 → Location: /ghost/, Set-Cookie: ghost-admin-api-session=...

  ▼
Ghost CMS (port 80, internal)
  express-session middleware verifies cookie signature using admin_session_secret,
  reads session_data.user_id, looks up user → admin panel loads authenticated.
```

---

## End-to-end request flow

### First visit (no session cookie)

1. Browser requests `https://blog.esamir.com/ghost/`.
2. Envoy's `oauth2` filter sees no `AccessToken-*` cookie → redirects to Authentik.
3. User authenticates with Authentik. Authentik redirects back to `/oauth2/callback`.
4. Envoy's `oauth2` filter completes the code exchange, stores the encrypted access token in an
   `AccessToken-*` cookie, and redirects the browser to `/ghost/`.
5. Browser requests `/ghost/` again — now carrying the `AccessToken-*` cookie.
6. Envoy's `oauth2` filter decrypts the cookie and injects `Authorization: Bearer <access_token>`
   into the request headers.
7. Envoy calls `ghost-auth-shim.Check` (ExtAuth). No `ghost-admin-api-session` cookie is present,
   so the slow path runs:
   - The service calls the Authentik userinfo endpoint with the Bearer token → resolves `email`.
   - Looks up the user in Ghost's MariaDB; confirms `status = "active"`.
   - Finds or creates a session row; signs the cookie.
   - Returns `DeniedResponse` 302 with `Set-Cookie: ghost-admin-api-session=s:<id>.<sig>`.
8. Browser receives the 302, stores the cookie, follows redirect to `/ghost/`.

### Subsequent visits (session cookie present)

1. Browser requests any `/ghost/*` URL, sending `ghost-admin-api-session=s:<id>.<sig>`.
2. Envoy calls `ghost-auth-shim.Check`. The fast path fires immediately — no DB or userinfo
   call. The `Authorization: Bearer` header is stripped from the request so it never reaches Ghost.
3. Ghost receives the request with the session cookie, verifies the HMAC signature against
   `admin_session_secret`, reads `session_data.user_id`, loads the user → serves the admin panel.

---

## Critical: Envoy filter chain ordering

### The problem

By default, Envoy Gateway places `ext_authz` at index `[0]` and `oauth2` at index `[1]`:

```
[0] envoy.filters.http.ext_authz   ← fires first — access token not yet decrypted
[1] envoy.filters.http.oauth2      ← fires second — too late
[2] envoy.filters.http.router
```

Because `ext_authz` runs before `oauth2` decrypts the `AccessToken-*` cookie, the `Check` request
arrives at `ghost-auth-shim` with no `Authorization: Bearer` header. The service can find no token
and fails open — every request fast-paths to Ghost unauthenticated.

### The fix: EnvoyPatchPolicy

An `EnvoyPatchPolicy` (JSON Patch `move`) swaps the two filters so `oauth2` runs first:

```yaml
# apps/ghost/overlays/default/home/envoy-patch.yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyPatchPolicy
metadata:
  name: oauth2-before-extauthz
  namespace: default          # must be the same namespace as the Gateway
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: http-gateway
  type: JSONPatch
  jsonPatches:
    - type: "type.googleapis.com/envoy.config.listener.v3.Listener"
      name: "default/http-gateway/https"
      operation:
        op: move
        from: "/filter_chains/0/filters/0/typed_config/http_filters/1"
        path: "/filter_chains/0/filters/0/typed_config/http_filters/0"
```

The indices (`/filter_chains/0/filters/0/…/1` and `…/0`) were confirmed against a live Envoy
`config_dump`. If the `SecurityPolicy` or `Gateway` is changed and the indices shift, re-run the
`apply-extauth-metadata-patch.sh` script to discover the new positions and update the patch.

### Enabling EnvoyPatchPolicy

`EnvoyPatchPolicy` is disabled in Envoy Gateway by default. It must be explicitly enabled in the
Envoy Gateway Helm values:

```yaml
# apps/envoy-gateway/base/values.yml
config:
  envoyGateway:
    apiVersion: gateway.envoyproxy.io/v1alpha1
    kind: EnvoyGateway
    extensionApis:
      enableEnvoyPatchPolicy: true
```

Without this, the policy is silently ignored and shows `reason: Disabled` in its status. After
enabling it, the status should show `reason: Programmed` / `Patches have been successfully applied`.

---

## Kubernetes configuration

### SecurityPolicy (oidc.yaml)

The `ghost-oidc` SecurityPolicy sits on the `ghost-admin` HTTPRoute. It configures two things in
a single resource:

- **OIDC** — handles authentication with Authentik, manages the `AccessToken-*` cookie, and
  forwards the decrypted access token as `Authorization: Bearer <token>` to downstream filters.
  `forwardAccessToken: true` is required; without it the Bearer header is never injected and
  ExtAuth sees no token.
- **extAuth** — wires `ghost-auth-shim` as the External Authorization backend.

```yaml
spec:
  oidc:
    provider:
      issuer: "https://auth.esamir.com/application/o/envoy-oidc/"
    clientID: "..."
    clientSecret:
      name: ghost-oidc
      namespace: ghost
    redirectURL: "https://blog.esamir.com/oauth2/callback"
    logoutPath: "/ghost/signout"
    forwardAccessToken: true
    scopes: [openid, profile, email]
  extAuth:
    grpc:
      backendRefs:
        - name: ghost-auth-shim
          port: 8080
```

### auth-shim Deployment (auth-shim.yaml)

Key environment variables:

| Variable | Purpose | Value |
|---|---|---|
| `GHOST_ADMIN_URL` | Internal Ghost URL (logged only, not currently used for requests) | `http://ghost.ghost.svc.cluster.local` |
| `DB_HOST` | MariaDB host | `mariadb.mariadb.svc.cluster.local` |
| `DB_NAME` | Database name | `ghost` |
| `DB_USER` | Database user | `ghost` |
| `DB_PASSWORD` | Database password (from Secret) | — |
| `LOG_LEVEL` | Verbosity | `debug` (set to `info` in production) |
| `SESSION_MAX_AGE_DAYS` | Session lifetime | `180` |
| `OIDC_USERINFO_URL` | Authentik userinfo endpoint | `https://auth.esamir.com/application/o/userinfo/` |

The `OIDC_USERINFO_URL` must match the `userinfo_endpoint` field in the provider's
`.well-known/openid-configuration` — **not** the application-specific userinfo path. Confirm with:

```bash
curl https://auth.esamir.com/application/o/envoy-oidc/.well-known/openid-configuration \
  | python3 -m json.tool | grep userinfo
```

---

## Go service implementation

### Token decoding via OIDC userinfo (oidctoken/decoder.go)

The access token forwarded by Envoy's `oauth2` filter is an opaque token (Authentik issues opaque
access tokens by default). It cannot be decoded locally as a JWT. Instead, the decoder calls the
OIDC userinfo endpoint with the Bearer token to resolve the email claim:

```
Authorization: Bearer <access_token>
GET https://auth.esamir.com/application/o/userinfo/
→ {"sub": "...", "email": "user@example.com", ...}
```

When `OIDC_USERINFO_URL` is empty (local dev), the decoder falls back to treating the access token
as a JWT and decoding its payload directly — no signature verification (Envoy already did that).

### ExtAuth Check RPC (extauth/server.go)

The `Check` method:

1. Reads `cookie` and `authorization` headers from `req.GetAttributes().GetRequest().GetHttp().GetHeaders()`.
2. Calls `auth.EnsureSession(ctx, cookieHeader, authHeader)`.
3. **Fast path** (`signedCookie == ""`): returns `OkResponse`, stripping the `Authorization` header
   so the Bearer token never leaks to Ghost.
4. **Slow path** (cookie returned): returns `DeniedResponse` 302 with `Set-Cookie`.
5. **Error path**: returns `OkResponse` (fail-open). Ghost renders its own login page as a
   safe fallback; requests are never hard-blocked.

Why `DeniedResponse` for the cookie redirect, not `OkResponse` with a header mutation: Envoy
Gateway strips `Set-Cookie` from `OkResponse` header mutations. A `DeniedResponse` (302) bypasses
the response-filter chain entirely, so `Set-Cookie` reaches the browser unmodified.

The `authorization` header fallback in `extractAuthHeader` also checks
`metadata_context["envoy.filters.http.oauth2"]["access_token"]` for environments where Envoy
writes the access token into filter metadata rather than request headers. In the current deployment,
the header path works (confirmed by `auth_source: authorization_header` in logs).

### Session management (mariadb/session_store.go)

#### Reading admin_session_secret

Ghost's express-session signs cookies with the value of the `admin_session_secret` key in the
`settings` table. The store reads this once at startup:

```sql
SELECT `value` FROM `settings` WHERE `key` = 'admin_session_secret' LIMIT 1
```

The value may or may not be JSON-encoded (i.e., stored with surrounding `"` quotes in the DB). The
startup code attempts a JSON-decode and falls back to the raw string if the decode fails. The
startup log records `json_decoded`, `raw_len`, `final_len`, `raw_head`, and `raw_tail` so you can
cross-check the value without leaking it.

#### Cookie signing

Replicates `cookie-signature.sign()` from Node.js exactly:

```
s:<session_id>.<base64_std(HMAC-SHA256(session_id, admin_session_secret)).trimRight("=")>
```

Both Go and Node.js use standard (not URL-safe) base64 for the signature. The session ID itself is
URL-safe base64 (32 chars from 24 random bytes, matching uid-safe's output).

#### Finding and refreshing sessions

`FindByUserID` returns the most recent session created within the `SESSION_MAX_AGE_DAYS` window.
When a session is found it immediately refreshes the row:

```sql
UPDATE sessions SET session_data = ?, updated_at = ? WHERE session_id = ?
```

This is intentional. Older rows may have been written before `verified: true` was added to the
`session_data` schema. Ghost 6.x checks `session_data.verified === true` and returns 403 if the
field is missing or false. Refreshing the data on every reuse ensures the row is always valid
regardless of when or how it was originally created, and also bumps `updated_at` in the same way
Ghost's own express-session middleware would.

#### session_data schema

The JSON blob written to the `session_data` column must match Ghost's internal schema exactly:

```json
{
  "cookie": {
    "originalMaxAge": 15552000000,
    "expires": "2026-11-13T23:28:01.011Z",
    "secure": true,
    "httpOnly": true,
    "path": "/ghost",
    "sameSite": "none"
  },
  "user_id": "6a0a4ec3a5492600013952c4",
  "verified": true,
  "origin": "",
  "user_agent": "",
  "ip": ""
}
```

`verified: true` is required. `origin`, `user_agent`, and `ip` are present in every Ghost-created
row but are not validated on authorization; empty strings are fine.

`sameSite` must be `"none"` (lowercase) — Ghost itself uses this value. `SameSite=None` requires
`Secure=true`, which we always include.

#### Creating new sessions

If no session exists for the user, `Create` generates:

- **Session ID**: 24 crypto-random bytes → 32-char URL-safe base64 (matches uid-safe).
- **Object ID** (row `id`): 4-byte big-endian Unix timestamp + 8 random bytes → 24 hex chars
  (matches Ghost's MongoDB-style primary keys).

---

## Debugging

### Useful log fields (LOG_LEVEL=debug)

| Log message | Meaning |
|---|---|
| `extauth check` | Fires on every request. Check `has_bearer_token`, `auth_source`, `has_cookie_header`. |
| `ghost-admin-api-session cookie present, passing through` | Fast path hit — ExtAuth is not involved further. |
| `no ghost session cookie found, verifying staff membership` | Slow path starting; shows `email`. |
| `reusing existing ghost session` | Existing DB row found for `user_id`; session_data refreshed. |
| `created ghost admin session` | New session row inserted. |
| `signed cookie for manual browser test` | Full `s:<id>.<sig>` value (debug level only). |
| `auth service error, failing open` | Something went wrong; request passed through unauthenticated. |

### Manually verifying HMAC

If Ghost returns 403 despite a valid-looking cookie, check that the signing secret matches what
Ghost is using:

```bash
# 1. Read the raw secret from MariaDB
kubectl -n mariadb exec -it deploy/mariadb -- mysql -u ghost -p ghost \
  -e "SELECT \`value\` FROM settings WHERE \`key\` = 'admin_session_secret';"

# 2. Cross-check against the startup log (raw_head / raw_tail fields)

# 3. Recompute the expected cookie value in Node.js:
node -e "
  const crypto = require('crypto');
  const sid = 'PASTE_SESSION_ID_FROM_LOGS';
  const secret = 'PASTE_SECRET_FROM_DB';
  const sig = crypto.createHmac('sha256', secret).update(sid).digest('base64').replace(/=+$/, '');
  console.log('s:' + sid + '.' + sig);
"
# Compare with the value in 'signed cookie for manual browser test' log.
```

### Clearing a stuck session

If the browser is stuck in a 403 loop (cookie present, Ghost rejecting it):

1. Open DevTools → Application → Cookies → `blog.esamir.com`.
2. Delete `ghost-admin-api-session`.
3. Optionally delete `AccessToken-*` and `IdToken-*` cookies to force a fresh Authentik flow.
4. Reload — the full auth cycle runs again, and `FindByUserID` will refresh the session_data.

### Verifying session_data in the DB

```bash
kubectl -n mariadb exec -it deploy/mariadb -- mysql -u ghost -p ghost \
  -e "SELECT session_id, LEFT(session_data, 300), updated_at
      FROM sessions
      ORDER BY updated_at DESC LIMIT 5\G"
```

Confirm `"verified":true` is present.

### Checking EnvoyPatchPolicy status

```bash
kubectl get envoypatchpolicy -n default oauth2-before-extauthz -o yaml
```

The `.status.conditions` should show `reason: Programmed`. `reason: Disabled` means
`enableEnvoyPatchPolicy: true` is not in the Envoy Gateway Helm values. `reason: Invalid` means
the patch indices are wrong — re-run `apply-extauth-metadata-patch.sh` to find the correct ones.

### Inspecting the live filter chain

```bash
# Find the Envoy proxy pod
POD=$(kubectl -n envoy-gateway-system get pods \
  -l 'gateway.envoyproxy.io/owning-gateway-name=http-gateway' \
  -o jsonpath='{.items[0].metadata.name}')

# Port-forward and dump the config
kubectl -n envoy-gateway-system port-forward pod/$POD 19001:19000 &
sleep 2
curl -s http://localhost:19001/config_dump | python3 -c "
import json, sys
cfg = json.load(sys.stdin)
for c in cfg['configs']:
  if 'ListenersConfigDump' not in c.get('@type',''):
    continue
  for dl in c.get('dynamic_listeners', []):
    l = dl.get('active_state', {}).get('listener', {})
    port = l.get('address', {}).get('socket_address', {}).get('port_value', 0)
    if port not in (443, 8443):
      continue
    for fc in l.get('filter_chains', []):
      for f in fc.get('filters', []):
        names = [x.get('name','') for x in f.get('typed_config',{}).get('http_filters',[])]
        print('\n'.join(f'[{i}] {n}' for i, n in enumerate(names)))
"
```

After the `EnvoyPatchPolicy` is applied you should see `oauth2` at index 0 and `ext_authz` at
index 1.

---

## What must not change

The following are invariants that the whole chain depends on:

- **`forwardAccessToken: true`** in the SecurityPolicy OIDC block. Without this, Envoy does not
  inject the Bearer header and ExtAuth sees no token.
- **`admin_session_secret`** in Ghost's `settings` table. This value is read once at proxy startup.
  If Ghost rotates it (e.g. DB restore, re-install), restart the `ghost-auth-shim` pod.
- **`enableEnvoyPatchPolicy: true`** in the Envoy Gateway Helm values. Without it the filter-order
  patch is silently ignored.
- **`EnvoyPatchPolicy` namespace `default`** — it must be in the same namespace as the `Gateway`
  resource (`http-gateway` lives in `default`).
- **`SESSION_MAX_AGE_DAYS`** — if changed, existing sessions that were created with a different max
  age will have their `session_data.cookie.originalMaxAge` refreshed on next reuse, which is fine.
  Do not change this to 0 or negative; the config validator will reject it.

---

## Deploy sequence

```bash
# 1. Go changes
go test ./...

# 2. Build and push
mage buildLinux
docker build -t ghcr.io/safaci2000/ghost-sso-proxy:main-<sha> .
docker push ghcr.io/safaci2000/ghost-sso-proxy:main-<sha>

# 3. Update image tag
#    Edit apps/ghost/overlays/default/home/auth-shim.yaml → image: ghcr.io/.../ghost-sso-proxy:main-<sha>

# 4. Commit both repos
#    ArgoCD syncs automatically. The SecurityPolicy and new image roll out together.

# 5. Verify
kubectl -n ghost rollout status deployment/ghost-auth-shim
kubectl -n ghost logs -l app=ghost-auth-shim --tail=50
```
