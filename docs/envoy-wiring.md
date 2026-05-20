# Envoy wiring reference

This document shows how `ghost-sso-proxy` is wired into Envoy Gateway. The actual manifests live in `nas-flux/apps/ghost/overlays/default/home/`.

## Overview

Only one Envoy Gateway CRD is required:

- `SecurityPolicy` — attaches the ExtAuth gRPC backend (`ghost-auth-shim`) to the `ghost-admin` HTTPRoute. Authentik handles authentication via forward auth; Envoy is not involved in the login flow.

There is no `oidc:` block in the SecurityPolicy, no `EnvoyPatchPolicy`, and no `/oauth2/callback` route.

## 1. HTTPRoute (`oidc.yaml`)

Routes `/ghost` traffic to the Ghost CMS backend. The SecurityPolicy below is attached to this route by name.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: ghost-admin
  namespace: ghost
spec:
  parentRefs:
    - name: http-gateway
      namespace: default
      sectionName: https
  hostnames:
    - blog.esamir.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /ghost
      backendRefs:
        - name: ghost
          port: 80
```

## 2. SecurityPolicy (`oidc.yaml`)

Attaches `ghost-auth-shim` as the ExtAuth backend for every request that matches the `ghost-admin` route.

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: ghost-oidc
  namespace: ghost
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: ghost-admin
  extAuth:
    grpc:
      backendRefs:
        - name: ghost-auth-shim
          port: 8080
```

No `oidc:` block. Authentik validates authentication via its forward auth endpoint, which `ghost-auth-shim` calls directly. Envoy sees only ext_authz in the filter chain.

## 3. ghost-auth-shim Deployment (`auth-shim.yaml`)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ghost-auth-shim
  namespace: ghost
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ghost-auth-shim
  template:
    metadata:
      labels:
        app: ghost-auth-shim
    spec:
      containers:
        - name: ghost-auth-shim
          image: ghcr.io/csg33k/ghost-sso-proxy:<tag>
          ports:
            - containerPort: 8080
              name: grpc
          env:
            - name: DB_HOST
              value: "mariadb.mariadb.svc.cluster.local"
            - name: DB_NAME
              value: "ghost"
            - name: DB_USER
              value: "ghost"
            - name: LOG_LEVEL
              value: "info"
            - name: SESSION_MAX_AGE_DAYS
              value: "30"
            - name: AUTHENTIK_FORWARD_AUTH_URL
              value: "https://auth.esamir.com/outpost.goauthentik.io/auth/traefik"
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: ghost-db
                  key: password
          readinessProbe:
            grpc:
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            grpc:
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 30
---
apiVersion: v1
kind: Service
metadata:
  name: ghost-auth-shim
  namespace: ghost
spec:
  selector:
    app: ghost-auth-shim
  ports:
    - name: grpc
      port: 8080
      targetPort: 8080
```

## 4. Authentik callback route (`authentik-callback-route.yaml`)

Authentik's proxyv2 uses a full OAuth2 PKCE flow. After the user authenticates on `auth.esamir.com`, Authentik redirects the browser to:

```
https://blog.esamir.com/outpost.goauthentik.io/callback?X-authentik-auth-callback=true
```

This request must reach `authentik-server` (in the `authentik` namespace) directly — it must **not** pass through the `ghost-oidc` SecurityPolicy, otherwise ext_authz fires on the callback and creates a redirect loop.

A separate HTTPRoute handles this, scoped to the `/outpost.goauthentik.io` prefix and with no SecurityPolicy attached:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: ghost-authentik-callback
  namespace: ghost
spec:
  parentRefs:
    - name: http-gateway
      namespace: default
      sectionName: https
  hostnames:
    - blog.esamir.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /outpost.goauthentik.io
      backendRefs:
        - name: authentik-server
          namespace: authentik
          port: 80
```

Because this is a cross-namespace backendRef (route in `ghost`, service in `authentik`), Gateway API requires a `ReferenceGrant` in the target namespace. This lives in `apps/auth/overlays/default/home/reference-grant.yaml`:

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: ghost-to-authentik-server
  namespace: authentik
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: ghost
  to:
    - group: ""
      kind: Service
      name: authentik-server
```

Without the ReferenceGrant, Envoy Gateway silently rejects the cross-namespace backend and the callback returns 500.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `AUTHENTIK_FORWARD_AUTH_URL` | **Yes** | Forward auth endpoint URL. Service panics at startup if unset. Obtain from [authentik-setup.md](authentik-setup.md). |
| `DB_HOST` | Yes | MariaDB hostname |
| `DB_NAME` | Yes | Ghost database name |
| `DB_USER` | Yes | Database user |
| `DB_PASSWORD` | Yes | Database password (mount from Secret) |
| `SESSION_MAX_AGE_DAYS` | No | Ghost session lifetime in days (default: 30). Short is fine — Authentik transparently renews Ghost sessions. |
| `LOG_LEVEL` | No | `debug` / `info` / `warn` / `error` (default: `info`) |

## Secret shapes

```yaml
# Ghost DB password
apiVersion: v1
kind: Secret
metadata:
  name: ghost-db
  namespace: ghost
stringData:
  password: <your-db-password>
```

No OIDC client secret is needed — the OIDC client secret was used by Envoy's oauth2 filter, which has been removed.

## Debugging

Enable debug logging (`LOG_LEVEL=debug`) to see per-request decisions:

```
level=DEBUG msg="ghost-admin-api-session cookie present, passing through"
level=INFO  msg="no ghost session cookie found, verifying staff membership" email=alice@example.com
level=INFO  msg="reusing existing ghost session" user_id=507f1f77bcf86cd799439011
level=INFO  msg="created ghost admin session" user_id=507f1f77bcf86cd799439011 email=alice@example.com
```

To verify the ExtAuth gRPC connection:

```bash
kubectl -n ghost logs -l app=ghost-auth-shim --tail=100 | grep -E "listening|authentik|error"
```

See [extauth-architecture.md](extauth-architecture.md) for full debugging procedures.
