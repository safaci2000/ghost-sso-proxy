# Kubernetes deployment guide

This guide covers a production-ready deployment of `ghost-sso-proxy` alongside Ghost and MariaDB on Kubernetes, using Envoy Gateway as the ingress controller and Authentik as the identity provider.

## Prerequisites

- Kubernetes 1.28+
- [Envoy Gateway](https://gateway.envoyproxy.io/) installed
- A MariaDB or MySQL instance (e.g., the [MariaDB Operator](https://mariadb.com/docs/skysql/connect/programming-languages/kubernetes/))
- Authentik running and reachable from inside the cluster
- `kubectl` and `helm` (optional)

## Namespace layout

```
namespace: ghost         # Ghost CMS + ghost-auth-shim
namespace: mariadb       # MariaDB
namespace: default       # Envoy Gateway http-gateway lives here
```

## 1. Ghost and MariaDB

Deploy Ghost using the official Helm chart or manifests. Ghost needs:

- A MariaDB database with `charset=utf8mb4`
- `NODE_ENV=production` and a valid `url` pointing to the public HTTPS hostname
- Mail configured (at minimum `Direct` transport for dev, SMTP for production)

After Ghost boots and you complete the setup wizard, it populates `admin_session_secret` in the `settings` table. `ghost-auth-shim` reads this value at startup to sign session cookies.

## 2. Authentik: create the Proxy Provider and Application

Before deploying the shim, set up Authentik. The `scripts/authentik-setup-ghost.py` script handles this automatically — see [authentik-setup.md](authentik-setup.md) for step-by-step instructions.

After running the script you will have:

- A **Proxy Provider** (`ghost-forward-auth`, forward auth / single application mode) targeting `https://blog.esamir.com`
- An **Application** (`ghost`, slug `ghost`) bound to that provider
- The provider assigned to the embedded proxy outpost

The forward auth URL to use in the deployment is:

```
https://auth.esamir.com/outpost.goauthentik.io/auth/traefik
```

> **Note:** Authentik 2026.x removed the per-application forward auth path (`/auth/application/<slug>/`). The proxyv2 embedded outpost only serves `/auth/traefik`.

## 3. Database credentials Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ghost-db
  namespace: ghost
type: Opaque
stringData:
  password: <your-db-password>
```

## 4. ghost-auth-shim Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ghost-auth-shim
  namespace: ghost
  labels:
    app: ghost-auth-shim
spec:
  replicas: 2                      # stateless — sessions live in MariaDB
  revisionHistoryLimit: 2
  selector:
    matchLabels:
      app: ghost-auth-shim
  template:
    metadata:
      labels:
        app: ghost-auth-shim
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: ghost-auth-shim
          image: ghcr.io/safaci2000/ghost-sso-proxy:<tag>
          imagePullPolicy: IfNotPresent
          ports:
            - name: grpc
              containerPort: 8080
              protocol: TCP
          env:
            - name: DB_HOST
              value: "mariadb.mariadb.svc.cluster.local"
            - name: DB_PORT
              value: "3306"
            - name: DB_NAME
              value: "ghost"
            - name: DB_USER
              value: "ghost"
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: ghost-db
                  key: password
            - name: LOG_LEVEL
              value: "info"
            - name: SESSION_MAX_AGE_DAYS
              value: "30"
            - name: AUTHENTIK_FORWARD_AUTH_URL
              value: "https://auth.esamir.com/outpost.goauthentik.io/auth/traefik"
          readinessProbe:
            grpc:
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
            failureThreshold: 3
          livenessProbe:
            grpc:
              port: 8080
            initialDelaySeconds: 15
            periodSeconds: 30
          resources:
            requests:
              cpu: 50m
              memory: 32Mi
            limits:
              cpu: 500m
              memory: 128Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
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
      protocol: TCP
```

## 5. Envoy Gateway resources

Apply the manifests from [envoy-wiring.md](envoy-wiring.md). Summary:

- **HTTPRoute** `ghost-admin` — matches `/ghost` on `blog.esamir.com`, routes to Ghost on port 80
- **SecurityPolicy** `ghost-oidc` — attaches `ghost-auth-shim:8080` as the ExtAuth backend for that route
- **HTTPRoute** `ghost-authentik-callback` — matches `/outpost.goauthentik.io` on `blog.esamir.com`, routes cross-namespace to `authentik-server:80` with **no SecurityPolicy** (the OAuth2 callback must not pass through ExtAuth)
- **ReferenceGrant** `ghost-to-authentik-server` (in the `authentik` namespace) — permits the cross-namespace backendRef above

No `EnvoyPatchPolicy` is needed. There is no `oidc:` block in the SecurityPolicy.

## 6. First-run checklist

After deploying:

1. Navigate to `https://blog.esamir.com/ghost` in a browser.
2. Envoy calls `ghost-auth-shim`. The shim calls Authentik's forward auth endpoint (`/auth/traefik`).
3. If no Authentik session exists, Authentik starts an OAuth2 PKCE flow — the shim forwards the `authentik_proxy_*` state cookie and redirects the browser to the Authentik login page.
4. Log in with the email of a Ghost staff member (created via the Ghost admin setup wizard).
5. Authentik redirects to `blog.esamir.com/outpost.goauthentik.io/callback`, completes the code exchange (handled by the `ghost-authentik-callback` route), then redirects back to `/ghost/`.
6. The shim resolves the email from Authentik, creates a Ghost session, and injects the cookie.
7. Ghost loads the admin panel pre-authenticated.

Check shim logs for confirmation:

```bash
kubectl -n ghost logs -l app=ghost-auth-shim --tail=50
# Should show: created ghost admin session  user_id=... email=you@example.com
```

## 7. Scaling considerations

The shim is stateless — all session state lives in MariaDB. Multiple replicas are safe. `FindByUserID` reuses any existing session created by another replica, so duplicate sessions are rare.

## 8. Upgrading

Rolling upgrades are safe. The shim reads `admin_session_secret` at startup; Ghost does not rotate it under normal operation. If you reset Ghost's database or re-install, restart the shim pods to pick up the new secret:

```bash
kubectl -n ghost rollout restart deployment/ghost-auth-shim
```

## 9. Monitoring

Key log fields (structured JSON at `LOG_LEVEL=info`):

| Field | Meaning |
|---|---|
| `email` | Authentik identity being authenticated |
| `user_id` | Ghost ObjectId of the staff user |
| `error` | Error detail when auth fails (shim fails open — request is not hard-blocked) |

The shim exposes only a gRPC port. Kubernetes gRPC health probes (`readinessProbe.grpc`) work natively from Kubernetes 1.24+.
