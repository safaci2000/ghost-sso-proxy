# Authentik setup guide

This guide covers how to configure Authentik to work with `ghost-sso-proxy` using the **forward auth** pattern, and how to use the setup script to automate that configuration.

---

## Overview

`ghost-sso-proxy` no longer uses Envoy's built-in oauth2 filter. Instead it calls Authentik's forward auth endpoint directly from the ExtAuth service. Authentik validates its own proxy session cookie, and if the user is authenticated it returns their email in the `X-Authentik-Email` response header. If not authenticated it returns a 302 redirect to the login flow.

This requires a **Proxy Provider** (forward auth, single application mode) in Authentik, an **Application** bound to that provider, and the provider assigned to the **embedded proxy outpost**.

---

## Prerequisites

- Authentik running and reachable (the script targets `https://auth.esamir.com` by default)
- An Authentik API token with **API** intent (see below)
- Python 3.11+ (no third-party packages required)
- macOS users: run `/Applications/Python\ 3.x/Install\ Certificates.command` once if you see SSL errors

### Generate an API token

1. Open Authentik → **Admin interface** → **Directory** → **Tokens**
2. Click **Create**
3. Set **Intent** to **API** — this is required; other intents (recovery, email, verification) will return 403
4. Copy the token key shown immediately after creation (displayed once only)

```bash
export AUTHENTIK_TOKEN=<your-api-token>
```

---

## The setup script

`scripts/authentik-setup-ghost.py` creates all three Authentik resources in a single run. It is idempotent: re-running it will skip resources that already exist and only patch what differs.

### Dry run first

Always do a dry run before making changes. This reads the API and prints exactly what would be created, without writing anything:

```bash
export AUTHENTIK_TOKEN=<your-api-token>
python3 scripts/authentik-setup-ghost.py --dry-run
```

Expected output:

```
── DRY RUN — no changes will be made ──────────────────────────────────────

Step 1: Flows
  Looking up flows: 'default-provider-authorization-implicit-consent' and 'default-provider-invalidation-flow' …
  ✓ Authorization flow PK:  8d2d9c9b-c081-47e5-9334-540f41775179
  ✓ Invalidation flow PK:   f1857c49-d3a8-41dd-ae13-ef46687175ad

Step 2: Proxy Provider
  Payload: {
    "name": "ghost-forward-auth",
    "authorization_flow": "8d2d9c9b-...",
    "invalidation_flow": "f1857c49-...",
    "mode": "forward_single",
    "external_host": "https://blog.esamir.com",
    "access_token_validity": "days=365",
    "refresh_token_validity": "days=365"
  }
  [dry-run] Would POST /providers/proxy/

Step 3: Application
  Payload: { "name": "ghost", "slug": "ghost", "provider": 0 }
  [dry-run] Would POST /core/applications/

Step 4: Outpost assignment
  ✓ Found outpost: 'authentik Embedded Outpost' (pk=...)
  [dry-run] Would PATCH outpost providers list

────────────────────────────────────────────────────────────────────────
Done. Set this in auth-shim.yaml and .env (local dev):

  AUTHENTIK_FORWARD_AUTH_URL: "https://auth.esamir.com/outpost.goauthentik.io/auth/traefik"

(dry-run: no resources were created)
```

### Live run

```bash
python3 scripts/authentik-setup-ghost.py
```

The script will:

1. Look up the authorization and invalidation flows in a single API call
2. Create the **Proxy Provider** `ghost-forward-auth` (forward auth, single application, `https://blog.esamir.com`)
3. Create the **Application** `ghost` (slug: `ghost`) bound to that provider
4. Add the provider to the **embedded proxy outpost**

### CLI flags

| Flag | Default | Purpose |
|---|---|---|
| `--dry-run` | — | Read-only mode; prints what would be created without writing |
| `--auth-flow SLUG` | `default-provider-authorization-implicit-consent` | Override the authorization flow slug |
| `--invalidation-flow SLUG` | `default-provider-invalidation-flow` | Override the invalidation flow slug |

If your Authentik instance uses non-default flow slugs, list what is available:

```bash
# Authorization flows
curl -s -H "Authorization: Bearer $AUTHENTIK_TOKEN" \
  "https://auth.esamir.com/api/v3/flows/instances/?designation=authorization" \
  | python3 -m json.tool | grep slug

# Invalidation flows
curl -s -H "Authorization: Bearer $AUTHENTIK_TOKEN" \
  "https://auth.esamir.com/api/v3/flows/instances/?designation=invalidation" \
  | python3 -m json.tool | grep slug
```

Then re-run:

```bash
python3 scripts/authentik-setup-ghost.py \
  --auth-flow my-custom-auth-flow \
  --invalidation-flow my-custom-invalidation-flow
```

---

## What the script creates

### Proxy Provider — `ghost-forward-auth`

| Setting | Value |
|---|---|
| Mode | Forward auth (single application) |
| External host | `https://blog.esamir.com` |
| Token validity | 365 days |
| Authorization flow | `default-provider-authorization-implicit-consent` |
| Invalidation flow | `default-provider-invalidation-flow` |

**Forward auth (single application)** means Authentik protects exactly one external host. The proxyv2 embedded outpost uses a full OAuth2 PKCE flow: on first visit it sets `authentik_proxy_*` state cookies and redirects to the authorize endpoint; after login it redirects the browser to `blog.esamir.com/outpost.goauthentik.io/callback`. That callback path must route to `authentik-server` — see `authentik-callback-route.yaml` and `reference-grant.yaml` in `nas-flux`.

### Application — `ghost`

| Setting | Value |
|---|---|
| Name | `ghost` |
| Slug | `ghost` |
| Provider | `ghost-forward-auth` (the provider above) |

### Outpost assignment

The script adds the provider to the **embedded proxy outpost** (`goauthentik.io/outposts/embedded`). If no embedded outpost exists it falls back to the first proxy outpost it finds. If no proxy outpost exists at all, it prints a warning and you must assign the provider to an outpost manually via the Authentik UI.

---

## After running the script

> **Note on the endpoint URL:** Authentik 2026.x removed the per-application forward auth path (`/auth/application/<slug>/`). The correct endpoint for the proxyv2 embedded outpost is now `/auth/traefik`, regardless of the application slug.

Set `AUTHENTIK_FORWARD_AUTH_URL` wherever the shim reads its config:

**`apps/ghost/overlays/default/home/auth-shim.yaml`** (Kubernetes):
```yaml
- name: AUTHENTIK_FORWARD_AUTH_URL
  value: "https://auth.esamir.com/outpost.goauthentik.io/auth/traefik"
```

**`.env`** (local dev):
```
AUTHENTIK_FORWARD_AUTH_URL=https://auth.esamir.com/outpost.goauthentik.io/auth/traefik
```

---

## Verify the configuration

### Check the provider exists

```bash
curl -s -H "Authorization: Bearer $AUTHENTIK_TOKEN" \
  "https://auth.esamir.com/api/v3/providers/proxy/?name=ghost-forward-auth" \
  | python3 -m json.tool | grep -E '"name"|"mode"|"external_host"'
```

Expected:
```json
"name": "ghost-forward-auth",
"mode": "forward_single",
"external_host": "https://blog.esamir.com",
```

### Check the application exists

```bash
curl -s -H "Authorization: Bearer $AUTHENTIK_TOKEN" \
  "https://auth.esamir.com/api/v3/core/applications/?slug=ghost" \
  | python3 -m json.tool | grep -E '"slug"|"name"'
```

### Test the forward auth endpoint directly

With a browser session active on `blog.esamir.com`, copy the Authentik session cookie value (`authentik_session`) from DevTools and test the endpoint:

```bash
curl -v \
  -H "Cookie: authentik_session=<your-session-cookie>" \
  -H "X-Forwarded-Host: blog.esamir.com" \
  -H "X-Forwarded-Proto: https" \
  -H "X-Forwarded-Uri: /ghost/" \
  "https://auth.esamir.com/outpost.goauthentik.io/auth/traefik"
```

- **200** + `X-Authentik-Email: you@example.com` → authenticated correctly
- **302** + `Location: https://auth.esamir.com/application/o/authorize/?...` + `Set-Cookie: authentik_proxy_*` → not authenticated; PKCE flow starting (expected without a session)

---

## Common errors

### `SSL: CERTIFICATE_VERIFY_FAILED` (macOS)

Python installed from python.org on macOS doesn't use the system certificate store by default. Fix:

```bash
/Applications/Python\ 3.13/Install\ Certificates.command
```

Adjust the version number to match your Python installation (`3.11`, `3.12`, etc.).

### `HTTP 403 — Token invalid/expired`

The API token was rejected. Most common cause: the token **Intent** is not set to **API**. Check in Authentik → Directory → Tokens → find your token → verify the Intent column shows **API**. Create a new token with the correct intent if needed.

### `No authorization flow found with slug '...'`

Your Authentik instance uses a different slug for the default auth flow. List available flows:

```bash
curl -s -H "Authorization: Bearer $AUTHENTIK_TOKEN" \
  "https://auth.esamir.com/api/v3/flows/instances/?designation=authorization" \
  | python3 -m json.tool | grep slug
```

Then pass the correct slug: `python3 scripts/authentik-setup-ghost.py --auth-flow <slug>`

### `No invalidation flow found with slug '...'`

Same as above for the invalidation flow:

```bash
curl -s -H "Authorization: Bearer $AUTHENTIK_TOKEN" \
  "https://auth.esamir.com/api/v3/flows/instances/?designation=invalidation" \
  | python3 -m json.tool | grep slug
```

Then: `python3 scripts/authentik-setup-ghost.py --invalidation-flow <slug>`

### `No proxy outpost found`

No proxy outpost exists in your Authentik instance. Create one manually:

1. Authentik → **Admin** → **Applications** → **Outposts** → **Create**
2. Type: **Proxy**
3. Add the `ghost-forward-auth` provider to it
4. Save

### `Application 'ghost' already exists but points to provider X`

The script will automatically PATCH the application to point to the newly created provider. No manual intervention needed — this is logged as a warning and handled.

---

## Decommissioning the old OIDC provider

After the forward auth migration is live and verified:

1. In Authentik → **Applications** → find the old `envoy-oidc` application → **Delete**
2. In Authentik → **Providers** → find the old OAuth2/OIDC provider → **Delete**
3. In Kubernetes → delete the `ghost-oidc` Secret (it held the OIDC client secret): `kubectl -n ghost delete secret ghost-oidc`

The `EnvoyPatchPolicy` (`oauth2-before-extauthz`) has already been deleted from `nas-flux` as part of Stage 6.
