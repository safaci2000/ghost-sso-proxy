# Ghost SSO: ExtAuth Architecture and Implementation Notes

This document is the authoritative reference for `ghost-sso-proxy`. It describes the current architecture (Envoy ExtAuth + Authentik forward auth), the design decisions behind it, and everything an operator needs to run and debug the system.

---

## Background: how we got here

### ExtProc → ExtAuth

The original design used Envoy's External Processor (`EnvoyExtensionPolicy` → `extProc`). The Envoy Gateway controller accepted the policy but never programmed an `ext_proc` filter into the data plane — a confirmed translation bug in the version in use. We replaced it with External Authorization (`SecurityPolicy` → `extAuth`), which uses a simpler unary `Check` RPC and is far more battle-tested in Envoy Gateway.

### oauth2 filter → Authentik forward auth

The first ExtAuth iteration used Envoy's built-in `oidc:` SecurityPolicy block to handle the Authentik login flow, then forwarded the decrypted access token to the shim as `Authorization: Bearer <token>`. The shim called Authentik's userinfo endpoint to resolve the email.

This required an `EnvoyPatchPolicy` to move the oauth2 filter before ext_authz in the HTTP filter chain. The patch used hardcoded filter-chain indices. When a new HTTPRoute was added to the cluster (Mastodon), the indices shifted, Envoy crash-looped, and the entire gateway went down.

The fix is the current design: remove the oauth2 filter entirely. The shim calls Authentik's **forward auth endpoint** directly, forwarding the browser's cookie header. Authentik validates its own proxy session cookie and returns the user's email — or a redirect URL if the user needs to log in. No filter ordering to manage, no `EnvoyPatchPolicy` needed.

---

## Current architecture

```
Browser
  │
  ▼
Envoy Gateway (http-gateway)
  │  HTTPS listener — single filter chain (no oauth2 filter):
  │    [0] envoy.filters.http.ext_authz   ← calls ghost-auth-shim (ExtAuth)
  │    [1] envoy.filters.http.router
  │
  ├─── SecurityPolicy (ghost-oidc)
  │      extAuth only: ghost-auth-shim:8080 (gRPC)
  │      (no oidc: block — Authentik handles auth via forward auth)
  │
  ▼
ghost-auth-shim (ghost-sso-proxy, this repo)
  │  implements envoy.service.auth.v3.Authorization
  │
  ├── Fast path: ghost-admin-api-session cookie already present
  │     → OkResponse immediately (no network calls)
  │
  └── Slow path: no ghost session cookie
        1. Call Authentik forward auth endpoint (HTTP GET)
           forwarding browser Cookie, X-Forwarded-Host/Proto/Uri
           ├── 200 + X-Authentik-Email: user@example.com
           │     → proceed to step 2
           └── 302 + Location: https://auth.esamir.com/application/o/authorize/?...
                   + Set-Cookie: authentik_proxy_*=<pkce-state>
                 → DeniedResponse 302 to that Location, forwarding Set-Cookie headers
                   (PKCE state cookies must reach the browser or the callback fails)
        2. SELECT users WHERE email = ? → confirm active staff member
        3. SELECT sessions WHERE user_id = ? → reuse existing row
           OR INSERT new session row
        4. Sign cookie: s:<session_id>.<base64(HMAC-SHA256(session_id, admin_session_secret))>
        5. DeniedResponse 302 → Location: /ghost/, Set-Cookie: ghost-admin-api-session=...

  ▼
Ghost CMS (port 80, internal)
  express-session middleware verifies cookie signature using admin_session_secret,
  reads session_data.user_id, looks up user → admin panel loads authenticated.
```

---

## End-to-end request flow

### First visit (no session cookie)

1. Browser requests `https://blog.esamir.com/ghost/`.
2. Envoy calls `ghost-auth-shim.Check` (ExtAuth). No `ghost-admin-api-session` cookie is present, so the slow path runs.
3. The shim calls `GET https://auth.esamir.com/outpost.goauthentik.io/auth/traefik` with the browser's Cookie header and `X-Forwarded-*` headers forwarded.
4. If no Authentik session exists: Authentik returns **302** + `Location: https://auth.esamir.com/application/o/authorize/?...` + `Set-Cookie: authentik_proxy_*=<pkce-state>`. The shim returns `DeniedResponse 302` to that URL, forwarding the `authentik_proxy_*` cookie so the browser can store the PKCE state token.
5. The browser authenticates with Authentik. After login, Authentik redirects to `https://blog.esamir.com/outpost.goauthentik.io/callback` — handled by the `ghost-authentik-callback` HTTPRoute (routes to `authentik-server`, no SecurityPolicy). The proxyv2 completes the code exchange and redirects back to the original URL with an Authentik session cookie.
6. Browser requests `/ghost/` again — now carrying the Authentik session cookie.
7. The shim calls Authentik forward auth again. Authentik returns **200** + `X-Authentik-Email: user@example.com`.
8. The shim looks up the user in Ghost's MariaDB, confirms `status = "active"`, finds or creates a session row, signs the cookie.
9. Returns `DeniedResponse 302` with `Set-Cookie: ghost-admin-api-session=s:<id>.<sig>; Path=/ghost; HttpOnly; Secure; SameSite=None`.
10. Browser stores the cookie, follows redirect to `/ghost/`.

### Subsequent visits (both session cookies present)

1. Browser requests any `/ghost/*` URL, sending both `authentik_session` and `ghost-admin-api-session`.
2. Envoy calls `ghost-auth-shim.Check`. The fast path fires immediately — cookie present, `OkResponse` returned.
3. No Authentik call. No DB hit. Ghost receives the request with the session cookie, verifies the HMAC, serves the admin panel.

### Ghost session expired (Authentik session still valid)

1. Browser requests `/ghost/` with `authentik_session` but without (or with expired) `ghost-admin-api-session`.
2. Slow path: shim calls Authentik forward auth → 200 + email (Authentik session is still valid, no login needed).
3. Shim creates a new Ghost session silently, returns 302 + `Set-Cookie`.
4. Browser stores the new cookie; user never sees a login prompt. Session renewal is fully transparent.

---

## Kubernetes configuration

### SecurityPolicy (`oidc.yaml`)

The `ghost-oidc` SecurityPolicy sits on the `ghost-admin` HTTPRoute. It now has a single job — wiring the ExtAuth backend:

```yaml
spec:
  extAuth:
    grpc:
      backendRefs:
        - name: ghost-auth-shim
          port: 8080
```

The `oidc:` block has been removed. Authentik handles authentication internally via the forward auth endpoint; Envoy is no longer involved in the login flow.

### HTTPRoute (`oidc.yaml`)

The `ghost-admin` HTTPRoute matches only `/ghost`:

```yaml
rules:
  - matches:
      - path:
          type: PathPrefix
          value: /ghost
    backendRefs:
      - name: ghost
        port: 80
```

The `/oauth2/callback` match was removed — it was only needed for Envoy's internal oauth2 token exchange, which is gone.

### auth-shim Deployment (`auth-shim.yaml`)

Key environment variables:

| Variable | Purpose | Value |
|---|---|---|
| `DB_HOST` | MariaDB host | `mariadb.mariadb.svc.cluster.local` |
| `DB_NAME` | Database name | `ghost` |
| `DB_USER` | Database user | `ghost` |
| `DB_PASSWORD` | Database password (from Secret) | — |
| `LOG_LEVEL` | Verbosity | `info` (use `debug` to see per-request decisions) |
| `SESSION_MAX_AGE_DAYS` | Ghost session lifetime | `30` |
| `AUTHENTIK_FORWARD_AUTH_URL` | Authentik forward auth endpoint (required) | `https://auth.esamir.com/outpost.goauthentik.io/auth/traefik` |

`AUTHENTIK_FORWARD_AUTH_URL` is required. The service panics at startup if it is not set. Use the `/auth/traefik` path — the per-application path (`/auth/application/<slug>/`) was removed in Authentik 2026.x.

Ghost session lifetime (`SESSION_MAX_AGE_DAYS`) can be short (30 days) because Authentik's proxy session (365 days) transparently re-creates Ghost sessions when they expire. Users are never prompted to log in again.

---

## Go service implementation

### Authentik forward auth client (`authentik/forward_auth.go`)

Implements the `secondary.ForwardAuthChecker` port. Makes a single HTTP GET to the forward auth endpoint with:

- `Cookie: <browser cookie header>` — forwards the browser's full cookie header so Authentik can find its `authentik_session` cookie
- `X-Forwarded-Host: blog.esamir.com`
- `X-Forwarded-Proto: https`
- `X-Forwarded-Uri: /ghost/` (the original request URI)

The HTTP client has `CheckRedirect` set to return `ErrUseLastResponse` — it does **not** follow redirects. A 302 is a valid response meaning "not authenticated"; the shim extracts the `Location` header and passes it to the browser.

Returns:
- `(email, "", nil, nil)` — authenticated
- `("", redirectURL, setCookies, nil)` — not authenticated; `setCookies` contains any `authentik_proxy_*` PKCE state cookies from Authentik's 302 response that must be forwarded to the browser
- `("", "", nil, err)` — network/protocol error; caller fails open

### ExtAuth Check RPC (`extauth/server.go`)

```
Check(ctx, req):
  1. Extract cookie header, :authority/:host, :scheme/X-Forwarded-Proto, :path
  2. If ghost-admin-api-session present → OkResponse (fast path)
  3. Call authentik.Check(ctx, cookieHeader, host, proto, uri)
     ├── redirectURL != "" → DeniedResponse 302 to redirectURL
     │                       forwarding any authentik_proxy_* Set-Cookie headers
     │                       (PKCE state — required for the OAuth2 callback)
     ├── err != nil        → OkResponse (fail-open)
     └── email != ""       → auth.EnsureSession(ctx, cookieHeader, email)
           ├── "" (fast path again) → OkResponse
           └── signedCookie        → DeniedResponse 302 /ghost/ + Set-Cookie
```

Two distinct redirect builders:
- `deniedRedirectTo(url, setCookies)` — 302 with Location + any Authentik PKCE state cookies forwarded as Set-Cookie headers. Used for Authentik login redirects.
- `deniedRedirectWithCookie(path, cookie)` — 302 to `/ghost/` with the Ghost session Set-Cookie. Used for Ghost session injection.

### Session management (`mariadb/session_store.go`)

#### Reading `admin_session_secret`

The store reads this once at startup:

```sql
SELECT `value` FROM `settings` WHERE `key` = 'admin_session_secret' LIMIT 1
```

The value may be JSON-encoded (surrounded by `"` quotes in the DB). The startup code attempts a JSON-decode and falls back to the raw string. Startup logs record `json_decoded`, `raw_len`, `final_len`, `raw_head`, and `raw_tail` so you can cross-check the value without leaking it.

#### Cookie signing

Replicates `cookie-signature.sign()` from Node.js exactly:

```
s:<session_id>.<base64_std(HMAC-SHA256(session_id, admin_session_secret)).trimRight("=")>
```

Both Go and Node.js use standard (not URL-safe) base64 for the signature. The session ID itself is URL-safe base64 (32 chars from 24 random bytes, matching uid-safe's output).

#### Finding and refreshing sessions

`FindByUserID` returns the most recent session created within the `SESSION_MAX_AGE_DAYS` window. When found it immediately refreshes the row:

```sql
UPDATE sessions SET session_data = ?, updated_at = ? WHERE session_id = ?
```

This ensures the `session_data` JSON is always current (Ghost 6.x requires `verified: true`) and bumps `updated_at` the same way Ghost's own express-session middleware would.

#### `session_data` schema

```json
{
  "cookie": {
    "originalMaxAge": 2592000000,
    "expires": "2026-06-18T00:00:00.000Z",
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

`verified: true` is required — Ghost 6.x returns 403 without it. `sameSite` must be `"none"` (lowercase). `SameSite=None` requires `Secure=true`, which is always included.

---

## Debugging

### Useful log fields (`LOG_LEVEL=debug`)

| Log message | Meaning |
|---|---|
| `extauth check` | Fires on every request. Check `has_ghost_cookie`. |
| `ghost-admin-api-session cookie present, passing through` | Fast path — no further processing. |
| `no ghost session cookie found, verifying staff membership` | Slow path starting; shows `email`. |
| `reusing existing ghost session` | Existing DB row found for `user_id`; session_data refreshed. |
| `created ghost admin session` | New session row inserted. |
| `signed cookie for manual browser test` | Full `s:<id>.<sig>` value — paste into DevTools to test manually. |
| `auth service error, failing open` | Error in the slow path; request passed through unauthenticated. |

### Checking Authentik forward auth connectivity

Test the endpoint from inside the cluster (the shim container may not have `wget`; use the Ghost container instead):

```bash
kubectl -n ghost exec deploy/ghost -- \
  curl -sv \
  -H "X-Forwarded-Host: blog.esamir.com" \
  -H "X-Forwarded-Proto: https" \
  -H "X-Forwarded-Uri: /ghost/" \
  "https://auth.esamir.com/outpost.goauthentik.io/auth/traefik" 2>&1 | grep -E "< HTTP|< Location|< Set-Cookie"
```

Expected without a valid Authentik session:
```
< HTTP/1.1 302 Found
< Location: https://auth.esamir.com/application/o/authorize/?...
< Set-Cookie: authentik_proxy_...=...; Path=/; HttpOnly; Secure; SameSite=Lax
```

If you see `HTTP/1.1 404` instead of 302, verify that `AUTHENTIK_FORWARD_AUTH_URL` ends with `/auth/traefik` (not `/auth/application/<slug>/` — that path was removed in Authentik 2026.x).

If you get a connection error, check that `auth.esamir.com` is reachable from the `ghost` namespace and that the URL in `AUTHENTIK_FORWARD_AUTH_URL` is correct.

### Manually verifying HMAC

If Ghost returns 403 despite a valid-looking cookie:

```bash
# 1. Read the raw secret from MariaDB
kubectl -n mariadb exec -it deploy/mariadb -- mysql -u ghost -p ghost \
  -e "SELECT \`value\` FROM settings WHERE \`key\` = 'admin_session_secret';"

# 2. Cross-check against the startup log (raw_head / raw_tail fields)

# 3. Recompute the expected cookie value
node -e "
  const crypto = require('crypto');
  const sid = 'PASTE_SESSION_ID_FROM_LOGS';
  const secret = 'PASTE_SECRET_FROM_DB';
  const sig = crypto.createHmac('sha256', secret).update(sid).digest('base64').replace(/=+$/, '');
  console.log('s:' + sid + '.' + sig);
"
```

Compare with the `signed cookie for manual browser test` log line.

### Clearing a stuck session

If the browser is stuck in a 403 loop:

1. Open DevTools → Application → Cookies → `blog.esamir.com`
2. Delete `ghost-admin-api-session`
3. Reload — the slow path runs, creates a fresh session with current `session_data`

Do **not** delete `authentik_session` unless you want to force a full re-login through Authentik.

### Verifying `session_data` in the DB

```bash
kubectl -n mariadb exec -it deploy/mariadb -- mysql -u ghost -p ghost \
  -e "SELECT session_id, LEFT(session_data, 300), updated_at
      FROM sessions
      ORDER BY updated_at DESC LIMIT 5\G"
```

Confirm `"verified":true` is present.

### Inspecting the live filter chain

```bash
POD=$(kubectl -n envoy-gateway-system get pods \
  -l 'gateway.envoyproxy.io/owning-gateway-name=http-gateway' \
  -o jsonpath='{.items[0].metadata.name}')

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

You should see `ext_authz` at index 0 and `router` at index 1. No `oauth2` filter. No `EnvoyPatchPolicy` is applied.

---

## What must not change

| Invariant | Why |
|---|---|
| `admin_session_secret` in Ghost's `settings` table | Read once at proxy startup. If Ghost rotates it (DB restore, re-install), restart `ghost-auth-shim`. |
| `AUTHENTIK_FORWARD_AUTH_URL` ends with `/auth/traefik` | Wrong path → 404 from Authentik; shim fails open and users reach Ghost unauthenticated. The per-application path (`/auth/application/<slug>/`) was removed in Authentik 2026.x. |
| `SESSION_MAX_AGE_DAYS` ≥ 1 | Config validator rejects 0 or negative. Changing this value is safe — `session_data` is refreshed on every session reuse. |
| Authentik Proxy Provider mode = `forward_single` | `forward_domain` mode rewrites the `X-Forwarded-Host` header and breaks the routing. |
| Authentik provider assigned to the embedded outpost | Without this, the forward auth endpoint returns 404. |

---

## Deploy sequence

```bash
# 1. Go changes
go test ./...
go test -race ./...

# 2. Build and push
mage buildLinux
docker build -t ghcr.io/safaci2000/ghost-sso-proxy:main-<sha> .
docker push ghcr.io/safaci2000/ghost-sso-proxy:main-<sha>

# 3. Update image tag in auth-shim.yaml
#    image: ghcr.io/safaci2000/ghost-sso-proxy:main-<sha>

# 4. Commit both repos (ghost-sso-proxy + nas-flux)
#    ArgoCD syncs automatically.

# 5. Verify
kubectl -n ghost rollout status deployment/ghost-auth-shim
kubectl -n ghost logs -l app=ghost-auth-shim --tail=50
```
