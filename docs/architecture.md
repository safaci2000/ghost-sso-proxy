# Architecture overview

## Problem

Ghost does not natively support OIDC or SSO. Its admin panel uses express-session cookies signed with a secret (`db_hash`) stored in the database. To log a user in, Ghost requires either a password POST or a pre-existing signed session cookie.

Envoy Gateway's OIDC filter can handle the provider round-trip and validate ID tokens, but it has no way to turn that validation into a Ghost session.

## Solution

`ghost-sso-proxy` is an Envoy [External Processor](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) (ExtProc) that runs as a sidecar or standalone gRPC service. Envoy calls it for every HTTP request that reaches Ghost's admin route. The proxy:

1. Checks whether a valid `ghost-admin-api-session` cookie is already present (fast path — no DB hit).
2. Decodes the OIDC ID token Envoy placed in the `IdToken-*` cookie (no re-verification; Envoy already validated the signature against the provider's JWKS).
3. Looks up the identity's email in Ghost's `users` table and confirms the account is active.
4. Finds or creates a session row in Ghost's `sessions` table.
5. Signs the session ID with Ghost's `db_hash` using the same algorithm as express-session (`s:<id>.<HMAC-SHA256>`).
6. Injects a `Set-Cookie` response header so the browser stores the cookie. Ghost's SPA boots already authenticated.

## Hexagonal architecture

The code follows a ports-and-adapters (hexagonal) layout so that the core business logic has zero infrastructure dependencies and is easy to test.

```
┌─────────────────────────────────────────────────────────────┐
│  PRIMARY ADAPTER                                            │
│  internal/adapters/primary/extproc/server.go               │
│  Envoy ExtProc gRPC server — drives AuthService            │
└───────────────────┬─────────────────────────────────────────┘
                    │ calls primary.AuthService interface
┌───────────────────▼─────────────────────────────────────────┐
│  CORE (no external deps)                                    │
│  internal/core/service/auth_service.go                     │
│  AuthService.EnsureSession()                               │
│    1. hasGhostSessionCookie? → return ""  (fast path)      │
│    2. decoder.Decode()        → Identity                   │
│    3. users.FindByEmail()     → User                       │
│    4. sessions.FindByUserID() → *Session (reuse or nil)    │
│    5. sessions.Create()       → Session                    │
│    6. return SignedCookieValue                              │
└───┬───────────────┬───────────────┬───────────────────────┘
    │               │               │  depends on secondary port interfaces
┌───▼──────┐ ┌──────▼──────┐ ┌──────▼───────────┐
│oidctoken │ │  mariadb    │ │  mariadb         │
│Decoder   │ │UserRepository│ │SessionStore      │
│          │ │             │ │                  │
│Decodes   │ │Queries      │ │Reads db_hash once│
│IdToken-* │ │users table  │ │Finds/creates     │
│JWT payload│ │by email     │ │session rows      │
│(no verify)│ │             │ │Signs cookies     │
└──────────┘ └─────────────┘ └──────────────────┘
```

## Request flow (happy path)

```
1. Browser →  GET /ghost
2. Envoy     →  OIDC filter: token valid, IdToken-<hash>=<jwt> cookie present
3. Envoy     →  ExtProc: stream.Send(RequestHeaders{cookie: "IdToken-..."})
4. Proxy     →  AuthService.EnsureSession(headers)
               a) No ghost-admin-api-session cookie → proceed
               b) Decode JWT payload → {email: "alice@example.com"}
               c) SELECT * FROM users WHERE email = 'alice@example.com'
               d) User.IsActive() → true
               e) SELECT ... FROM sessions WHERE user_id = ? ORDER BY created_at DESC
               f) Row found? → reuse. Not found? → INSERT new row, sign cookie
5. Proxy     →  stream.Send(RequestHeaders CONTINUE, await response phase)
6. Envoy     →  forwards request to Ghost; Ghost responds 200
7. Envoy     →  stream.Send(ResponseHeaders{...})
8. Proxy     →  stream.Send(ResponseHeaders CONTINUE + Set-Cookie mutation)
9. Browser   →  stores ghost-admin-api-session cookie
10. Browser  →  Ghost SPA boots, validates cookie via db_hash → authenticated ✓
```

## Cookie signing

Ghost uses [express-session](https://github.com/expressjs/session) with cookie signing enabled. The signed cookie format is:

```
s:<session_id>.<base64(HMAC-SHA256(session_id, db_hash))>
```

where trailing `=` padding is stripped from the base64 segment. The proxy reads `db_hash` once at startup from Ghost's `settings` table and uses it for all subsequent signing. This avoids a DB round-trip per request.

## Session ID format

express-session uses [uid-safe](https://github.com/crypto-utils/uid-safe) to generate session IDs: 24 crypto-random bytes encoded as URL-safe base64 without padding (32 characters). The proxy matches this format exactly.

Ghost's primary key (`id` column) is a MongoDB-style 24-hex-char ObjectId: 4-byte big-endian Unix timestamp + 8 random bytes. The proxy generates this format for new session rows.

## Security notes

- The proxy trusts Envoy's OIDC validation and does **not** re-verify JWT signatures. This is intentional: signature verification is Envoy's responsibility. Ensure ExtProc is only reachable from Envoy (not publicly exposed).
- The proxy only reads/writes the Ghost `users` and `sessions` tables. It does not touch passwords, content, or any other data.
- Sessions have no explicit server-side expiry in this implementation (matching Ghost's default behavior). The `Max-Age=86400` cookie attribute is a client-side convenience only.
