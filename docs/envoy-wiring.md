# Envoy wiring reference

This document shows how to wire `ghost-sso-proxy` into an Envoy Gateway deployment. The exact resource names will vary; adjust them to match your cluster.

## Overview

Two Envoy Gateway CRDs are required:

- `SecurityPolicy` — configures the OIDC filter that validates ID tokens before your ExtProc runs.
- `EnvoyExtensionPolicy` — attaches the ExtProc gRPC backend to the HTTPRoute for the Ghost admin path.

## 1. Deploy the proxy

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ghost-sso-proxy
  namespace: ghost
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ghost-sso-proxy
  template:
    metadata:
      labels:
        app: ghost-sso-proxy
    spec:
      containers:
        - name: ghost-sso-proxy
          image: ghcr.io/safaci2000/ghost-sso-proxy:latest
          ports:
            - name: grpc
              containerPort: 8080
          env:
            - name: DB_HOST
              value: "mariadb.mariadb.svc.cluster.local"
            - name: DB_NAME
              value: "ghost"
            - name: DB_USER
              valueFrom:
                secretKeyRef:
                  name: ghost-db-credentials
                  key: username
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: ghost-db-credentials
                  key: password
            - name: GRPC_PORT
              value: "8080"
            - name: LOG_LEVEL
              value: "info"
          readinessProbe:
            grpc:
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: ghost-sso-proxy
  namespace: ghost
spec:
  selector:
    app: ghost-sso-proxy
  ports:
    - name: grpc
      port: 8080
      targetPort: grpc
```

## 2. SecurityPolicy (OIDC)

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: ghost-admin-oidc
  namespace: ghost
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: ghost-admin          # must match your HTTPRoute name
  oidc:
    provider:
      issuer: "https://accounts.example.com"   # your OIDC issuer
    clientID: "ghost-admin-client"
    clientSecret:
      name: ghost-oidc-client-secret           # Secret with key "client-secret"
    scopes:
      - openid
      - email
      - profile
    # Redirect the browser back to Ghost after the OIDC flow.
    redirectURL: "https://ghost.example.com/oauth2/callback"
    # Forward the validated ID token to ExtProc via an IdToken-* cookie.
    forwardAccessToken: false
```

## 3. EnvoyExtensionPolicy (ExtProc)

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyExtensionPolicy
metadata:
  name: ghost-sso-extproc
  namespace: ghost
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: ghost-admin
  extProc:
    - backendRefs:
        - name: ghost-sso-proxy
          namespace: ghost
          port: 8080
      processingMode:
        request:
          headers: SEND          # proxy inspects request cookies
        response:
          headers: SKIP          # proxy uses ImmediateResponse in the request phase;
                                 # it never needs the response phase. SEND would route
                                 # the ImmediateResponse through the OIDC filter chain,
                                 # which strips Set-Cookie and delivers it empty.
      failOpen: true             # pass through if the proxy is unavailable
      messageTimeout: 5s
```

## 4. HTTPRoute

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: ghost-admin
  namespace: ghost
spec:
  parentRefs:
    - name: my-gateway
      namespace: envoy-gateway-system
  hostnames:
    - "ghost.example.com"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /ghost
      backendRefs:
        - name: ghost
          port: 2368
    # Let Envoy handle the OIDC callback before ExtProc sees it.
    - matches:
        - path:
            type: PathPrefix
            value: /oauth2/callback
      backendRefs:
        - name: ghost
          port: 2368
```

## Processing mode details

| Phase | Mode | Why |
|---|---|---|
| Request headers | `SEND` | Proxy reads the `cookie` header to find `IdToken-*` and check for an existing `ghost-admin-api-session`. |
| Response headers | `SKIP` | Proxy delivers `Set-Cookie` via an `ImmediateResponse` 302 redirect in the **request** phase — the response phase is never used. Setting this to `SEND` routes the `ImmediateResponse` through Envoy's response filter chain, where the OIDC SecurityPolicy strips `Set-Cookie`, leaving it blank. |
| Request body | `SKIP` | Not needed. |
| Response body | `SKIP` | Not needed. |

## Secret shapes

```yaml
# Ghost DB credentials
apiVersion: v1
kind: Secret
metadata:
  name: ghost-db-credentials
  namespace: ghost
stringData:
  username: ghost
  password: <db-password>

# OIDC client secret
apiVersion: v1
kind: Secret
metadata:
  name: ghost-oidc-client-secret
  namespace: ghost
stringData:
  client-secret: <oidc-client-secret>
```

## Debugging

Enable debug logging on the proxy (`LOG_LEVEL=debug`) to see per-request decisions:

```
level=DEBUG msg="ghost-admin-api-session cookie present, passing through"
level=INFO  msg="no ghost session cookie found, verifying staff membership" email=alice@example.com
level=INFO  msg="reusing existing ghost session" user_id=507f1f77bcf86cd799439011
level=INFO  msg="created ghost admin session" user_id=507f1f77bcf86cd799439011 email=alice@example.com
```

To inspect the raw ExtProc stream, use `grpcurl` (see [local-testing.md](local-testing.md)).
