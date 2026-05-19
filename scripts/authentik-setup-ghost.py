#!/usr/bin/env python3
"""
authentik-setup-ghost.py
========================
Creates the Authentik resources needed for the ghost-sso-proxy forward auth flow:

  1. Proxy Provider  — "ghost-forward-auth"  (forward auth, single app, blog.esamir.com)
  2. Application     — "ghost"               (slug: ghost, bound to the provider above)
  3. Outpost         — adds the new provider to the embedded proxy outpost

At the end it prints the AUTHENTIK_FORWARD_AUTH_URL value to drop into auth-shim.yaml.

Usage
-----
  export AUTHENTIK_TOKEN=<your-api-token>
  python3 scripts/authentik-setup-ghost.py

  # Dry-run (reads only, prints what would be created):
  python3 scripts/authentik-setup-ghost.py --dry-run

Generate a token in Authentik:
  Admin → Directory → Tokens → Create  (intent: API)
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

# ── Configuration ──────────────────────────────────────────────────────────────

AUTHENTIK_URL   = "https://auth.esamir.com"
EXTERNAL_HOST   = "https://blog.esamir.com"
PROVIDER_NAME   = "ghost-forward-auth"
APP_NAME        = "ghost"
APP_SLUG        = "ghost"

# Ghost session cookies are short-lived because ghost-sso-proxy re-creates them
# transparently via forward auth. The Authentik proxy session is long-lived so
# users are never prompted to re-authenticate.
TOKEN_VALIDITY  = "days=365"

# The authorization flow Authentik uses when a user needs to log in.
# Uses the standard implicit-consent flow; override via --auth-flow if your
# Authentik instance uses a different slug.
DEFAULT_AUTH_FLOW_SLUG = "default-provider-authorization-implicit-consent"

# The invalidation flow Authentik uses when a session is ended (logout/token revocation).
# This field is required by the Authentik API when creating a provider.
DEFAULT_INVALIDATION_FLOW_SLUG = "default-provider-invalidation-flow"

# ── HTTP helpers ───────────────────────────────────────────────────────────────

def api(token: str, method: str, path: str, body: dict | None = None) -> dict:
    url = f"{AUTHENTIK_URL}/api/v3{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")
        print(f"\n✗ HTTP {e.code} {method} {url}", file=sys.stderr)
        print(f"  {body_text}", file=sys.stderr)
        sys.exit(1)


def get(token, path):     return api(token, "GET",   path)
def post(token, path, b): return api(token, "POST",  path, b)
def patch(token, path, b):return api(token, "PATCH", path, b)


# ── Step helpers ───────────────────────────────────────────────────────────────

def find_flows(token: str, auth_slug: str, invalidation_slug: str) -> tuple[str, str]:
    """Return (auth_flow_pk, invalidation_flow_pk) in a single API traversal.

    Fetches all flows with page_size=100 (covers any realistic Authentik instance
    in one round-trip) and scans for both slugs at once instead of issuing two
    separate filtered requests.
    """
    print(f"  Looking up flows: {auth_slug!r} and {invalidation_slug!r} …")
    auth_pk = None
    inv_pk = None
    page = 1
    while True:
        result = get(token, f"/flows/instances/?page_size=100&page={page}")
        for flow in result.get("results", []):
            if flow["slug"] == auth_slug:
                auth_pk = flow["pk"]
            if flow["slug"] == invalidation_slug:
                inv_pk = flow["pk"]
            if auth_pk and inv_pk:
                break
        if (auth_pk and inv_pk) or not result.get("next"):
            break
        page += 1

    if not auth_pk:
        print(f"\n✗ No authorization flow found with slug {auth_slug!r}.", file=sys.stderr)
        print("  List available flows with:", file=sys.stderr)
        print(f"    curl -s -H 'Authorization: Bearer $AUTHENTIK_TOKEN' \\", file=sys.stderr)
        print(f"         '{AUTHENTIK_URL}/api/v3/flows/instances/' | python3 -m json.tool", file=sys.stderr)
        print("  Then re-run with --auth-flow <slug>", file=sys.stderr)
        sys.exit(1)
    if not inv_pk:
        print(f"\n✗ No invalidation flow found with slug {invalidation_slug!r}.", file=sys.stderr)
        print("  List available flows with:", file=sys.stderr)
        print(f"    curl -s -H 'Authorization: Bearer $AUTHENTIK_TOKEN' \\", file=sys.stderr)
        print(f"         '{AUTHENTIK_URL}/api/v3/flows/instances/' | python3 -m json.tool", file=sys.stderr)
        print("  Then re-run with --invalidation-flow <slug>", file=sys.stderr)
        sys.exit(1)

    print(f"  ✓ Authorization flow PK:  {auth_pk}")
    print(f"  ✓ Invalidation flow PK:   {inv_pk}")
    return auth_pk, inv_pk


def find_existing_provider(token: str) -> dict | None:
    """Return the proxy provider with exactly PROVIDER_NAME, or None.
    The API name filter is a contains match, so we verify the exact name."""
    result = get(token, f"/providers/proxy/?name={PROVIDER_NAME}")
    for p in result.get("results", []):
        if p["name"] == PROVIDER_NAME:
            return p
    return None


def create_provider(token: str, flow_pk: str, invalidation_flow_pk: str, dry_run: bool) -> dict:
    """Create (or find existing) the Proxy Provider and return it."""
    existing = find_existing_provider(token)
    if existing:
        print(f"  ✓ Provider already exists (pk={existing['pk']}), skipping creation.")
        return existing

    payload = {
        "name":                   PROVIDER_NAME,
        "authorization_flow":     flow_pk,
        "invalidation_flow":      invalidation_flow_pk,
        "mode":                   "forward_single",
        "external_host":          EXTERNAL_HOST,
        "access_token_validity":  TOKEN_VALIDITY,
        "refresh_token_validity": TOKEN_VALIDITY,
    }
    print(f"  Payload: {json.dumps(payload, indent=4)}")
    if dry_run:
        print("  [dry-run] Would POST /providers/proxy/")
        return {"pk": 0, "name": PROVIDER_NAME}

    provider = post(token, "/providers/proxy/", payload)
    print(f"  ✓ Provider created (pk={provider['pk']})")
    return provider


def find_existing_app(token: str) -> dict | None:
    """Return the app with exactly APP_SLUG, or None.
    The API slug filter is a contains match, so we verify the exact slug."""
    result = get(token, f"/core/applications/?slug={APP_SLUG}")
    for app in result.get("results", []):
        if app["slug"] == APP_SLUG:
            return app
    return None


def create_application(token: str, provider_pk: int, dry_run: bool) -> dict:
    """Create the Application, or update its provider if it already exists."""
    existing = find_existing_app(token)
    if existing:
        current_provider = existing.get("provider")
        if current_provider == provider_pk:
            print(f"  ✓ Application {APP_SLUG!r} already exists and points to the correct provider, skipping.")
        else:
            print(f"  ! Application {APP_SLUG!r} exists but points to provider {current_provider!r}.")
            print(f"    Updating to new Proxy Provider (pk={provider_pk}) …")
            if dry_run:
                print(f"  [dry-run] Would PATCH /core/applications/{existing['slug']}/")
            else:
                patch(token, f"/core/applications/{existing['slug']}/", {"provider": provider_pk})
                print(f"  ✓ Application updated.")
        return existing

    payload = {
        "name":     APP_NAME,
        "slug":     APP_SLUG,
        "provider": provider_pk,
    }
    print(f"  Payload: {json.dumps(payload, indent=4)}")
    if dry_run:
        print("  [dry-run] Would POST /core/applications/")
        return {"slug": APP_SLUG, "name": APP_NAME}

    app = post(token, "/core/applications/", payload)
    print(f"  ✓ Application created (slug={app['slug']})")
    return app


def assign_to_outpost(token: str, provider_pk: int, dry_run: bool) -> None:
    """Add the provider to the embedded proxy outpost."""
    print("  Looking up embedded proxy outpost …")
    result = get(token, "/outposts/instances/?managed=goauthentik.io/outposts/embedded")
    outposts = result.get("results", [])
    if not outposts:
        # Fall back: find any proxy outpost
        result = get(token, "/outposts/instances/?type=proxy")
        outposts = result.get("results", [])

    if not outposts:
        print("  ✗ No proxy outpost found — assign the provider to an outpost manually.", file=sys.stderr)
        return

    outpost = outposts[0]
    outpost_pk = outpost["pk"]
    outpost_name = outpost["name"]
    current_providers = outpost.get("providers", [])
    print(f"  ✓ Found outpost: {outpost_name!r} (pk={outpost_pk})")

    if provider_pk in current_providers:
        print(f"  ✓ Provider already assigned to outpost, skipping.")
        return

    updated_providers = current_providers + [provider_pk]
    print(f"  Assigning provider {provider_pk} → outpost {outpost_pk} …")
    if dry_run:
        print("  [dry-run] Would PATCH outpost providers list")
        return

    patch(token, f"/outposts/instances/{outpost_pk}/", {"providers": updated_providers})
    print(f"  ✓ Provider added to outpost.")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Read-only: print what would be created without making changes")
    parser.add_argument("--auth-flow", default=DEFAULT_AUTH_FLOW_SLUG, metavar="SLUG",
                        help=f"Authorization flow slug (default: {DEFAULT_AUTH_FLOW_SLUG})")
    parser.add_argument("--invalidation-flow", default=DEFAULT_INVALIDATION_FLOW_SLUG, metavar="SLUG",
                        help=f"Invalidation flow slug (default: {DEFAULT_INVALIDATION_FLOW_SLUG})")
    args = parser.parse_args()

    token = os.environ.get("AUTHENTIK_TOKEN", "").strip()
    if not token:
        print("Error: AUTHENTIK_TOKEN environment variable is not set.", file=sys.stderr)
        print("  export AUTHENTIK_TOKEN=<your-api-token>", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        print("── DRY RUN — no changes will be made ──────────────────────────────────────")

    print()
    print("Step 1: Flows")
    flow_pk, invalidation_flow_pk = find_flows(token, args.auth_flow, args.invalidation_flow)

    print()
    print("Step 2: Proxy Provider")
    provider = create_provider(token, flow_pk, invalidation_flow_pk, args.dry_run)

    print()
    print("Step 3: Application")
    create_application(token, provider["pk"], args.dry_run)

    print()
    print("Step 4: Outpost assignment")
    assign_to_outpost(token, provider["pk"], args.dry_run)

    forward_auth_url = f"{AUTHENTIK_URL}/outpost.goauthentik.io/auth/traefik"
    print()
    print("─" * 72)
    print("Done. Set this in auth-shim.yaml (Stage 6) and .env (local dev):")
    print()
    print(f"  AUTHENTIK_FORWARD_AUTH_URL: \"{forward_auth_url}\"")
    print()
    if args.dry_run:
        print("(dry-run: no resources were created)")


if __name__ == "__main__":
    main()
