# Local testing guide

This guide walks through verifying that `ghost-sso-proxy` works correctly against a local Ghost + MariaDB instance. The Authentik forward auth call can be bypassed by pointing `AUTHENTIK_FORWARD_AUTH_URL` at a local stub server.

## Prerequisites

- Docker and Docker Compose
- Go 1.23+
- `grpcurl` (`brew install grpcurl` / `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`)
- `mysql` client or `mariadb` CLI (optional, for direct DB inspection)

---

## Step 1 — Start Ghost and MariaDB

```bash
docker compose up -d

# Tail Ghost logs until you see "Ghost is running in development mode"
docker compose logs -f ghost
```

Ghost's first-run setup populates `admin_session_secret` in the `settings` table automatically.

## Step 2 — Complete the Ghost setup wizard

Open <http://localhost:2368/ghost> in a browser. Work through the setup wizard and create at least one staff user (the one you will test with).

> **Note:** If Ghost shows a "Maintenance" page, it is still running migrations. Wait ~15 seconds and refresh.

## Step 3 — Start a stub Authentik forward auth server

The shim needs a forward auth endpoint that returns `X-Authentik-Email`. A simple Python stub covers this for local testing:

```python
# stub_authentik.py
from http.server import HTTPServer, BaseHTTPRequestHandler

EMAIL = "you@example.com"   # must match a Ghost staff user

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Authentik-Email", EMAIL)
        self.end_headers()
    def log_message(self, *_): pass   # suppress request logs

HTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
```

```bash
python3 stub_authentik.py &
```

## Step 4 — Configure and start the shim

```bash
cp .env.example .env
```

Edit `.env` to point at the stub:

```
DB_HOST=127.0.0.1
DB_USER=ghost
DB_PASSWORD=ghostpassword
DB_NAME=ghost
LOG_LEVEL=debug
SESSION_MAX_AGE_DAYS=30
AUTHENTIK_FORWARD_AUTH_URL=http://127.0.0.1:9000/outpost.goauthentik.io/auth/traefik
```

Start the shim:

```bash
go run ./cmd
```

You should see:

```
level=INFO msg="authentik forward auth configured" forward_auth_url=http://127.0.0.1:9000/outpost.goauthentik.io/auth/traefik
level=INFO msg="ghost-sso-proxy listening" port=8080
```

## Step 5 — Send a synthetic ExtAuth Check request with grpcurl

```bash
grpcurl \
  -plaintext \
  -d '{
    "attributes": {
      "request": {
        "http": {
          "headers": {
            ":authority": "blog.esamir.com",
            ":scheme":    "https",
            ":path":      "/ghost/",
            "cookie":     "other=val"
          }
        }
      }
    }
  }' \
  localhost:8080 \
  envoy.service.auth.v3.Authorization/Check
```

Expected response — the shim creates a Ghost session and returns a 302 with `Set-Cookie`:

```json
{
  "status": {},
  "deniedResponse": {
    "status": { "code": 302 },
    "headers": [
      { "header": { "key": "Location", "value": "/ghost/" } },
      { "header": {
          "key": "Set-Cookie",
          "value": "ghost-admin-api-session=s:<id>.<hmac>; Path=/ghost; HttpOnly; Secure; SameSite=None; Max-Age=2592000"
      }}
    ]
  }
}
```

### Fast path (ghost cookie already present)

Send the returned cookie value back in a second request:

```bash
grpcurl \
  -plaintext \
  -d '{
    "attributes": {
      "request": {
        "http": {
          "headers": {
            ":authority": "blog.esamir.com",
            ":scheme":    "https",
            ":path":      "/ghost/",
            "cookie":     "ghost-admin-api-session=s:<id>.<hmac>"
          }
        }
      }
    }
  }' \
  localhost:8080 \
  envoy.service.auth.v3.Authorization/Check
```

Expected: `{"status": {}, "okResponse": {}}` — fast path, no Authentik or DB call.

### Authentik redirect path

Stop the stub and test fail-open:

```bash
kill %1   # stop stub_authentik.py
```

Send a Check request. The shim should fail open and return `okResponse` (request passes through unauthenticated). Ghost will render its own login page as a safe fallback.

To test the redirect path explicitly, modify the stub to return 302:

```python
# stub_authentik_redirect.py
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "https://auth.esamir.com/if/flow/default-authentication-flow/")
        self.end_headers()
    def log_message(self, *_): pass

HTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
```

The shim should return a `deniedResponse` 302 with `Location: https://auth.esamir.com/if/flow/...` and no `Set-Cookie` header.

## Step 6 — Verify the session in the database

```bash
docker compose exec db \
  mariadb -ughost -pghostpassword ghost \
  -e "SELECT session_id, user_id, LEFT(session_data, 200), created_at
      FROM sessions ORDER BY created_at DESC LIMIT 5\G"
```

Confirm:
- A row was inserted
- `session_data` contains `"verified":true`
- `user_id` matches the Ghost staff user you created in Step 2

## Step 7 — Manually test the cookie in a browser

Copy the `s:<id>.<hmac>` value from the grpcurl response. In DevTools (Application → Cookies), set:

| Name | `ghost-admin-api-session` |
|---|---|
| Value | `s:<id>.<hmac>` (the full signed value) |
| Domain | `localhost` |
| Path | `/ghost` |

Navigate to <http://localhost:2368/ghost>. Ghost should accept the cookie and show the admin panel without prompting for a password.

If Ghost returns 403, the HMAC signing secret is mismatched. Check the startup log for `raw_head` / `raw_tail` fields and compare against the DB value:

```bash
docker compose exec db \
  mariadb -ughost -pghostpassword ghost \
  -e "SELECT \`value\` FROM settings WHERE \`key\` = 'admin_session_secret';"
```

## Step 8 — Run unit tests

No database or running services needed:

```bash
go test -v -race ./...
```

All tests should pass in a few seconds.

---

## Troubleshooting

**`panic: config: required environment variable "AUTHENTIK_FORWARD_AUTH_URL" is not set`**
Add `AUTHENTIK_FORWARD_AUTH_URL=http://127.0.0.1:9000/` to your `.env` file.

**`panic: config: required environment variable "DB_USER" is not set`**
Copy `.env.example` to `.env` and verify it is in the working directory when you run `go run ./cmd`.

**`mariadb: ping failed`**
Make sure the compose stack is up (`docker compose ps`) and that `DB_HOST=127.0.0.1` (not `localhost`) in your `.env`. The Go MySQL driver on Linux resolves `localhost` as a Unix socket path.

**`mariadb: reading admin_session_secret from settings: sql: no rows in result set`**
Ghost has not finished its first-run setup. Complete the setup wizard at <http://localhost:2368/ghost> and restart the shim.

**grpcurl: `Failed to dial target host`**
Verify the shim is running (`go run ./cmd`) and listening on port 8080. Check for conflicts with `lsof -i :8080`.

**grpcurl: `unknown service envoy.service.auth.v3.Authorization`**
Use the `-plaintext` flag (the shim does not use TLS locally).
