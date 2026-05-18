# Local testing guide

This guide walks through verifying that `ghost-sso-proxy` is correctly wired to a local Ghost + MariaDB instance. No real OIDC provider is needed — we simulate the IdToken cookie by hand.

## Prerequisites

- Docker and Docker Compose
- Go 1.23+
- `grpcurl` (`brew install grpcurl` / `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`)
- `mysql` client or `mariadb` CLI (optional, for direct DB inspection)

## Step 1 — Start Ghost and MariaDB

```bash
docker compose up -d

# Tail Ghost logs until you see "Ghost is running in development mode"
docker compose logs -f ghost
```

Ghost first-run setup runs automatically on the first boot and populates `db_hash` in the `settings` table.

## Step 2 — Complete the Ghost setup wizard

Open <http://localhost:2368/ghost> in a browser. Work through the setup wizard and create at least one staff user (the one you will test with).

> **Note:** If Ghost shows a "Maintenance" page, it is still running migrations. Wait ~15 seconds and refresh.

## Step 3 — Confirm the proxy can read `db_hash`

```bash
cp .env.example .env
# .env should already have the right values for local compose:
#   DB_HOST=127.0.0.1  DB_USER=ghost  DB_PASSWORD=ghostpassword ...
```

Run the proxy in verbose mode:

```bash
LOG_LEVEL=debug go run ./cmd
```

You should see a log line like:

```
level=INFO msg="ghost-sso-proxy listening" port=8080
```

If you see `mariadb: reading db_hash from settings`, the DB connection succeeded and `db_hash` was loaded. If it panics with a missing env var, double-check your `.env` file.

## Step 4 — Build a test JWT

Construct a minimal unsigned JWT whose payload contains your staff user's email. The proxy does **not** re-verify the signature (Envoy does that upstream), so we can use a dummy signature.

```bash
# Payload: {"email":"you@example.com","sub":"test-sub"}
PAYLOAD=$(printf '{"email":"you@example.com","sub":"test-sub"}' \
  | base64 -w0 | tr '+/' '-_' | tr -d '=')

# Build a 3-segment JWT (header.payload.fakesig)
HEADER=$(printf '{"alg":"RS256","typ":"JWT"}' \
  | base64 -w0 | tr '+/' '-_' | tr -d '=')

TOKEN="${HEADER}.${PAYLOAD}.fakesig"
echo "Token: $TOKEN"
```

Replace `you@example.com` with the email of the Ghost staff user you created.

## Step 5 — Send a synthetic ExtProc request with grpcurl

The proxy uses Envoy's External Processor proto. Send a `ProcessingRequest` with a `RequestHeaders` body containing the fake IdToken cookie:

```bash
COOKIE="IdToken-deadbeef=${TOKEN}"

grpcurl \
  -plaintext \
  -proto vendor/envoy/service/ext_proc/v3/external_processor.proto \
  -d @ \
  localhost:8080 \
  envoy.service.ext_proc.v3.ExternalProcessor/Process <<EOF
{
  "request_headers": {
    "headers": {
      "headers": [
        { "key": "cookie", "value": "${COOKIE}" },
        { "key": ":path", "value": "/ghost" }
      ]
    }
  }
}
EOF
```

> **Tip:** If you don't have the proto files locally, use `buf` or point grpcurl at the `go-control-plane` vendor directory. Alternatively, use the `--import-path` flag.

A successful response looks like:

```json
{
  "requestHeaders": {
    "response": { "status": "CONTINUE" }
  }
}
```

If you then send a second message on the same stream (simulating the response phase), the proxy should respond with a `Set-Cookie` mutation:

```json
{
  "responseHeaders": {
    "response": {
      "status": "CONTINUE",
      "headerMutation": {
        "setHeaders": [
          {
            "header": {
              "key": "Set-Cookie",
              "value": "ghost-admin-api-session=s:<id>.<hmac>; Path=/ghost; HttpOnly; Secure; SameSite=Lax; Max-Age=86400"
            }
          }
        ]
      }
    }
  }
}
```

## Step 6 — Verify the session in the database

Check that a row was inserted into Ghost's `sessions` table:

```bash
docker compose exec db \
  mariadb -ughost -pghostpassword ghost \
  -e "SELECT session_id, user_id, created_at FROM sessions ORDER BY created_at DESC LIMIT 5\G"
```

You should see your new session row.

## Step 7 — Manually test the cookie in a browser

Copy the `s:<id>.<hmac>` value from the grpcurl response. In your browser's DevTools (Application → Cookies), set:

| Name | `ghost-admin-api-session` |
|---|---|
| Value | `s:<id>.<hmac>` (the full signed value) |
| Domain | `localhost` |
| Path | `/ghost` |

Navigate to <http://localhost:2368/ghost>. Ghost should accept the cookie and show the admin panel without prompting for a password.

## Step 8 — Run unit tests

No database needed:

```bash
go test -v -race ./...
```

All tests should pass in a few seconds.

## Troubleshooting

**`panic: config: required environment variable "DB_USER" is not set`**
Copy `.env.example` to `.env` and make sure it is in the working directory when you run `go run ./cmd`.

**`mariadb: ping failed`**
Make sure the compose stack is up (`docker compose ps`) and that `DB_HOST=127.0.0.1` (not `localhost`) in your `.env` — the Go MySQL driver on Linux resolves `localhost` as a Unix socket path.

**`mariadb: reading db_hash from settings: sql: no rows in result set`**
Ghost has not finished its first-run setup. Complete the setup wizard at <http://localhost:2368/ghost> and restart the proxy.

**`oidc token decode: no OIDC identity token found in request cookies`**
Normal — the proxy logs this at DEBUG level when no `IdToken-*` cookie is present (e.g., static assets, the OIDC callback round-trip). It is not an error.

**grpcurl: `Failed to dial target host`**
Verify the proxy is running (`go run ./cmd`) and listening on port 8080. Check for port conflicts with `lsof -i :8080`.
