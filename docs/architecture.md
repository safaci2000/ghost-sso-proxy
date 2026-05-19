# Architecture overview

## Problem

Ghost does not natively support OIDC or SSO. Its admin panel uses express-session cookies signed with a secret (`admin_session_secret`) stored in the database. To log a user in, Ghost requires either a password POST or a pre-existing signed session cookie.

## Solution

`ghost-sso-proxy` is an Envoy [External Authorization](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) (ExtAuth) service. Envoy calls it for every request that reaches Ghost's admin route via a `SecurityPolicy`. The proxy:

1. Checks whether a valid `ghost-admin-api-session` cookie is already present — fast path, no network calls.
2. Calls the Authentik forward auth endpoint, forwarding the browser's cookie header so Authentik can validate its own proxy session cookie.
3. If unauthenticated, returns a 302 redirect to the Authentik login flow.
4. If authenticated, looks up the user's email in Ghost's `users` table and confirms the account is active.
5. Finds or creates a session row in Ghost's `sessions` table.
6. Signs the session ID using the same algorithm as express-session: `s:<id>.<base64(HMAC-SHA256(id, admin_session_secret))>`.
7. Returns a `DeniedResponse` 302 redirect to `/ghost/` with `Set-Cookie`. Ghost's SPA boots already authenticated.

## Hexagonal architecture

The code follows a ports-and-adapters (hexagonal) layout so the core business logic has zero infrastructure dependencies and is easy to test.

```
┌─────────────────────────────────────────────────────────────┐
│  PRIMARY ADAPTER                                            │
│  internal/adapters/primary/extauth/server.go               │
│  Envoy ExtAuth gRPC server — drives AuthService            │
│    1. Fast path: ghost cookie present → OkResponse         │
│    2. Call Authentik forward auth → email or redirectURL   │
│    3. If redirectURL → DeniedResponse 302 (login flow)     │
│    4. If email → AuthService.EnsureSession()               │
└───────────────────┬─────────────────────────────────────────┘
                    │ calls primary.AuthService interface
┌───────────────────▼─────────────────────────────────────────┐
│  CORE (no external deps)                                    │
│  internal/core/service/auth_service.go                     │
│  AuthService.EnsureSession(cookieHeader, email)            │
│    1. hasGhostSessionCookie? → return ""  (fast path)      │
│    2. users.FindByEmail()     → User                       │
│    3. sessions.FindByUserID() → *Session (reuse or nil)    │
│    4. sessions.Create()       → Session                    │
│    5. return SignedCookieValue                              │
└───┬─────────────────────────────┬───────────────────────────┘
    │                             │  depends on secondary port interfaces
┌───▼──────────────────┐ ┌───────▼──────────────────────────┐
│  authentik           │ │  mariadb                         │
│  forward_auth.go     │ │  UserRepository + SessionStore   │
│                      │ │                                  │
│  Calls Authentik     │ │  Queries users table by email    │
│  forward auth HTTP   │ │  Reads admin_session_secret once │
│  endpoint; returns   │ │  Finds/creates session rows      │
│  email or redirect   │ │  Signs cookies                   │
└──────────────────────┘ └──────────────────────────────────┘
```

## Request flow (happy path — first visit)

```
1. Browser        → GET /ghost/ (no ghost-admin-api-session cookie)
2. Envoy          → ExtAuth Check RPC → ghost-auth-shim
3. ghost-auth-shim → Authentik forward auth endpoint
                     (forwarding browser Cookie header)
4. Authentik      → 200 + X-Authentik-Email: user@example.com
5. ghost-auth-shim → Ghost MariaDB: confirm user active, find/create session
6. ghost-auth-shim → DeniedResponse 302 /ghost/ + Set-Cookie: ghost-admin-api-session=s:<id>.<sig>
7. Browser        → stores cookie, follows redirect to /ghost/
8. Envoy          → ExtAuth Check RPC (ghost cookie now present) → OkResponse (fast path)
9. Ghost          → verifies HMAC, loads admin panel ✓
```

## Request flow (subsequent visits)

```
1. Browser        → GET /ghost/* (ghost-admin-api-session present)
2. Envoy          → ExtAuth Check RPC → ghost-auth-shim
3. ghost-auth-shim → fast path: cookie present → OkResponse immediately
                     (no Authentik call, no DB hit)
4. Ghost          → verifies HMAC, serves admin panel ✓
```

## Cookie signing

Ghost uses [express-session](https://github.com/expressjs/session) with cookie signing enabled. The signed cookie format is:

```
s:<session_id>.<base64(HMAC-SHA256(session_id, admin_session_secret))>
```

where trailing `=` padding is stripped from the base64 segment. The proxy reads `admin_session_secret` once at startup from Ghost's `settings` table and uses it for all subsequent signing.

Note: the signing key is `admin_session_secret` — not `db_hash`. The `db_hash` setting is used only by Ghost for password-reset tokens.

## Session ID format

express-session uses [uid-safe](https://github.com/crypto-utils/uid-safe) to generate session IDs: 24 crypto-random bytes encoded as URL-safe base64 without padding (32 characters). The proxy matches this format exactly.

Ghost's primary key (`id` column) is a MongoDB-style 24-hex-char ObjectId: 4-byte big-endian Unix timestamp + 8 random bytes. The proxy generates this format for new session rows.

## Security notes

- The proxy forwards the browser's cookie header verbatim to Authentik's forward auth endpoint. Authentik validates its own session cookie and is the source of truth for identity.
- The proxy only reads/writes Ghost's `users` and `sessions` tables. It does not touch passwords, content, or any other data.
- `DeniedResponse` is used for the cookie redirect (not `OkResponse` with header mutation) because Envoy Gateway strips `Set-Cookie` from `OkResponse` mutations. A `DeniedResponse` 302 bypasses the response-filter chain so `Set-Cookie` reaches the browser unmodified.
- The proxy fails open on Authentik connectivity errors: if the forward auth call fails, the request passes through unauthenticated rather than hard-blocking. Ghost renders its own login page as a safe fallback.
