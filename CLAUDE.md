# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

`ghost-sso-proxy` is a gRPC service that bridges Authentik authentication into Ghost admin sessions. It runs as an Envoy ExtAuth server: Envoy calls it for every request on the Ghost admin HTTPRoute via a `SecurityPolicy`, the shim validates the browser's Authentik session by calling Authentik's forward auth endpoint, looks the user up in Ghost's MariaDB, creates or reuses a session row, and injects a signed `ghost-admin-api-session` cookie — all without touching Ghost's source code.

The cookie signing replicates express-session's format exactly: `s:<session_id>.<base64(HMAC-SHA256(session_id, admin_session_secret))>` where `admin_session_secret` is read once at startup from Ghost's `settings` table. (Not `db_hash` — that setting is only used for password-reset tokens.)

**Current deployed state:** Authentik forward auth is live. The shim calls `https://auth.esamir.com/outpost.goauthentik.io/auth/traefik` directly — no Envoy oauth2 filter, no `EnvoyPatchPolicy`. The `SecurityPolicy` has only an `extAuth:` block.

---

## Build and test commands

```bash
# Run all unit tests (no database required)
go test ./...
go test -race ./...
go test -v -run TestSignCookie ./internal/adapters/secondary/mariadb/  # single test

# Build
mage build        # → bin/ghost-sso-proxy (current OS/arch)
mage buildLinux   # → bin/ghost-sso-proxy (linux/amd64, used by Dockerfile)
mage clean

# Run locally (requires .env — copy from .env.example)
go run ./cmd

# Release validation
goreleaser check
goreleaser release --snapshot --clean  # local snapshot, no publish

# Docker
docker build -t ghost-sso-proxy .
docker compose up -d   # starts Ghost + MariaDB for local dev
```

---

## Architecture

The project uses **hexagonal architecture** (ports and adapters). The core service has zero external dependencies; all infrastructure is behind interfaces.

```
cmd/main.go                       ← wires everything together, starts gRPC server
config/config.go                  ← env-var config; DSN() builds the DB connection string
internal/core/domain/             ← pure types: User, Session, Identity, sentinel errors
internal/core/ports/primary/      ← AuthService interface (driven by the primary adapter)
internal/core/ports/secondary/    ← interfaces: UserRepository, SessionStore, ForwardAuthChecker
internal/core/service/auth_service.go  ← AuthService.EnsureSession() — the only business logic
internal/adapters/primary/
  extauth/   ← Envoy ExtAuth gRPC server — implements authv3.AuthorizationServer
internal/adapters/secondary/
  authentik/ ← Authentik forward auth HTTP client (ForwardAuthChecker)
  mariadb/user_repository.go      ← SELECT from Ghost's users table by email
  mariadb/session_store.go        ← reads admin_session_secret, finds/creates session rows, signs cookies
```

### Request flow through `Check` (one ExtAuth RPC = one HTTP request)

```
1. ghost-admin-api-session cookie already present → OkResponse immediately (fast path, no network calls)
2. Call Authentik forward auth endpoint (HTTP GET to AUTHENTIK_FORWARD_AUTH_URL)
   forwarding browser Cookie header + X-Forwarded-Host/Proto/Uri
   ├── 200 + X-Authentik-Email → authenticated; proceed to step 3
   └── 302 + Location + Set-Cookie: authentik_proxy_* → not authenticated
         Return DeniedResponse 302 to Location, forwarding the authentik_proxy_* PKCE
         state cookies (required for the OAuth2 callback to complete)
3. auth.EnsureSession(ctx, cookieHeader, email):
   a. ghost session cookie already present → return "" → OkResponse
   b. users.FindByEmail → confirm status = "active"
   c. sessions.FindByUserID → reuse most-recent session within SESSION_MAX_AGE_DAYS
   d. sessions.Create → generate session ID + ObjectId, INSERT, sign cookie
   e. Return signed cookie; ExtAuth issues DeniedResponse 302 /ghost/ + Set-Cookie
```

**Why `DeniedResponse` redirect instead of header mutation:** Envoy Gateway strips `Set-Cookie` from `OkResponse` header mutations. A `DeniedResponse` (302) bypasses the response-filter chain entirely so `Set-Cookie` is delivered to the browser unmodified.

### Authentik forward auth endpoint

Authentik 2026.x proxyv2 serves the forward auth endpoint at:

```
https://auth.esamir.com/outpost.goauthentik.io/auth/traefik
```

The per-application path (`/auth/application/<slug>/`) was removed in Authentik 2026.x. Always use `/auth/traefik`.

The proxyv2 uses an OAuth2 PKCE flow. On first visit it returns a 302 with `Set-Cookie: authentik_proxy_*` state cookies. These **must** be forwarded to the browser in the `DeniedResponse` or the callback at `blog.esamir.com/outpost.goauthentik.io/callback` will fail with "invalid state".

### `ForwardAuthChecker` port

```go
// internal/core/ports/secondary/forward_auth_checker.go
type ForwardAuthChecker interface {
    Check(ctx context.Context, cookieHeader, host, proto, uri string) (email, redirectURL string, setCookies []string, err error)
}
```

- `(email, "", nil, nil)` — authenticated
- `("", redirectURL, setCookies, nil)` — not authenticated; `setCookies` holds `authentik_proxy_*` PKCE state cookies to forward
- `("", "", nil, err)` — network/protocol error; caller fails open

---

## Key implementation details

- **Session ID format:** 24 crypto-random bytes → 32-char URL-safe base64 (matches uid-safe used by express-session)
- **ObjectId format:** 4-byte big-endian Unix timestamp + 8 random bytes → 24 hex chars (matches Ghost's MongoDB-style primary keys)
- **DB connection:** Both `UserRepository` and `SessionStore` share a single `*sql.DB` pool (5 max open, 2 idle, 5-min lifetime) opened in `cmd/main.go` and passed to both constructors.
- **`admin_session_secret`** is read once at startup via `NewSessionStore` and used as the express-session HMAC signing key. Ghost never rotates it in normal operation. If it changes (e.g. DB restore), restart the proxy.
- **Fail-open:** If the Authentik forward auth call fails (network error, timeout), the shim returns `OkResponse` and lets the request through unauthenticated. Ghost renders its own login page as a safe fallback.

---

## Testing approach

All tests are pure unit tests using only the standard library — no database, no running services. Secondary ports are mocked with simple local structs in `*_test.go` files. The `mariadb` package tests unexported functions directly (same package, `package mariadb`).

Key test files:
- `internal/adapters/primary/extauth/server_test.go` — full coverage of Check RPC paths including Authentik cookie forwarding
- `internal/adapters/secondary/authentik/forward_auth_test.go` — 200/302/error cases + Set-Cookie passthrough
- `internal/core/service/auth_service_test.go` — EnsureSession logic
- `internal/adapters/secondary/mariadb/` — session signing, ObjectId generation

---

## nas-flux layout (`apps/ghost/overlays/default/home/`)

| File | Purpose |
|---|---|
| `oidc.yaml` | `ghost-admin` HTTPRoute (`/ghost` → Ghost:80) + `ghost-oidc` SecurityPolicy (extAuth only, no `oidc:` block) |
| `auth-shim.yaml` | ghost-auth-shim Deployment + Service |
| `httproute.yaml` | Public blog HTTPRoute (`/` → Ghost:80, no SecurityPolicy) |
| `authentik-callback-route.yaml` | `ghost-authentik-callback` HTTPRoute: `/outpost.goauthentik.io` on `blog.esamir.com` → `authentik-server:80` cross-namespace, **no SecurityPolicy** |
| `secrets.yaml` | ExternalSecret for ghost-db |
| `kustomization.yaml` | Wires all of the above |

The callback route must have no SecurityPolicy — ExtAuth firing on the OAuth2 callback creates a redirect loop.

`apps/auth/overlays/default/home/reference-grant.yaml` — `ReferenceGrant` in the `authentik` namespace permitting the `ghost` namespace HTTPRoute to use `authentik-server` as a cross-namespace backendRef. Required by Gateway API; without it Envoy Gateway silently rejects the backend.

---

## Authentik configuration

A **Proxy Provider** (`ghost-forward-auth`) is configured in Authentik:
- Mode: **Forward auth (single application)**
- External host: `https://blog.esamir.com`
- Token validity: 365 days

The provider is assigned to the **embedded proxy outpost**. Run `scripts/authentik-setup-ghost.py` to create/update all Authentik resources automatically. See `docs/authentik-setup.md` for details.

---

## Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AUTHENTIK_FORWARD_AUTH_URL` | **Yes** | — | `https://auth.esamir.com/outpost.goauthentik.io/auth/traefik` — panics at startup if unset |
| `DB_HOST` | Yes | `mariadb.mariadb.svc.cluster.local` | MariaDB hostname |
| `DB_PORT` | No | `3306` | MariaDB port |
| `DB_NAME` | Yes | `ghost` | Ghost database name |
| `DB_USER` | **Yes** | — | Database user |
| `DB_PASSWORD` | **Yes** | — | Database password |
| `SESSION_MAX_AGE_DAYS` | No | `30` | Ghost session lifetime. Short is fine — Authentik transparently renews Ghost sessions. |
| `LOG_LEVEL` | No | `info` | `debug` / `info` / `warn` / `error` |
| `GRPC_PORT` | No | `8080` | gRPC listen port |

---

## Local dev environment

See `docs/local-testing.md` for a step-by-step guide including a stub Authentik server, synthetic `grpcurl` ExtAuth requests, and browser cookie verification.

The `.devcontainer/` setup starts Ghost + MariaDB alongside the Go shell automatically. `DB_HOST` must be `127.0.0.1` (not `localhost`) when connecting from the host to a Docker container on Linux — the Go MySQL driver treats `localhost` as a Unix socket path.

---

## Release

Releases use GoReleaser (`.goreleaser.yml`). Multi-arch binaries (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64) and multi-arch Docker manifests are pushed to GHCR. Tag with `git tag vX.Y.Z && git push origin vX.Y.Z` to trigger.
