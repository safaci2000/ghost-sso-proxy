# Kubernetes deployment guide

This guide covers a production-ready deployment of `ghost-sso-proxy` alongside Ghost and MariaDB on Kubernetes. Envoy Gateway is assumed as the ingress controller.

## Prerequisites

- Kubernetes 1.28+
- [Envoy Gateway](https://gateway.envoyproxy.io/) installed
- A MariaDB or MySQL instance (e.g., the [MariaDB Operator](https://mariadb.com/docs/skysql/connect/programming-languages/kubernetes/))
- An OIDC provider (Okta, Dex, Auth0, Google, etc.) with a configured client
- `kubectl` and `helm` (optional)

## Namespace layout

```
namespace: ghost         # Ghost CMS + ghost-sso-proxy
namespace: mariadb       # MariaDB (if using the MariaDB Operator)
namespace: envoy-gateway-system  # Envoy Gateway control plane
```

## 1. Ghost and MariaDB

Deploy Ghost using the official Helm chart or manifests. Ghost needs:

- A MariaDB database with `charset=utf8mb4`.
- `NODE_ENV=production` and a valid `url` config pointing to the public HTTPS hostname.
- Mail configured (at minimum `Direct` transport for dev, SMTP for production).

After Ghost boots and you complete the setup wizard, it populates `db_hash` in the `settings` table. The proxy reads this value at startup.

## 2. Database credentials Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ghost-db-credentials
  namespace: ghost
type: Opaque
stringData:
  username: ghost
  password: <your-db-password>
```

## 3. Proxy deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ghost-sso-proxy
  namespace: ghost
  labels:
    app: ghost-sso-proxy
    version: v1
spec:
  replicas: 2                      # multiple replicas are safe; sessions live in the DB
  selector:
    matchLabels:
      app: ghost-sso-proxy
  template:
    metadata:
      labels:
        app: ghost-sso-proxy
        version: v1
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: ghost-sso-proxy
          image: ghcr.io/<owner>/ghost-sso-proxy:v0.1.0
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
  name: ghost-sso-proxy
  namespace: ghost
spec:
  selector:
    app: ghost-sso-proxy
  ports:
    - name: grpc
      port: 8080
      targetPort: grpc
      protocol: TCP
```

## 4. Envoy Gateway resources

Apply the SecurityPolicy, EnvoyExtensionPolicy, and HTTPRoute from [envoy-wiring.md](envoy-wiring.md).

## 5. OIDC provider setup

Configure your OIDC provider with:

- **Allowed redirect URI:** `https://ghost.example.com/oauth2/callback`
- **Requested scopes:** `openid email profile`
- **Token endpoint auth method:** `client_secret_post` (or `client_secret_basic`)
- **ID token claims:** ensure `email` is included (most providers include it by default when `email` scope is requested)

The proxy uses only the `email` claim from the ID token. It does **not** use the access token.

## 6. First-run checklist

After deploying:

1. Navigate to `https://ghost.example.com/ghost` in a browser.
2. Envoy redirects you to your OIDC provider.
3. Log in with the email of a Ghost staff member (created via the Ghost admin wizard).
4. Envoy validates the token; the proxy intercepts the request, creates a session, and injects the cookie.
5. Ghost loads the admin panel pre-authenticated.

Check proxy logs for confirmation:

```
level=INFO msg="created ghost admin session" user_id=<id> email=you@example.com
```

## 7. Scaling considerations

The proxy is stateless (all state lives in MariaDB). You can run multiple replicas safely. The `FindByUserID` call reuses an existing session if one was created by another replica, so duplicate sessions are unlikely under normal traffic.

## 8. Upgrading

Rolling upgrades are safe. The proxy reads `db_hash` at startup; Ghost does not rotate this value under normal operation. If you reset Ghost's `db_hash` (e.g., database restore), restart the proxy pods to pick up the new value.

## 9. Monitoring

The proxy emits structured JSON logs (when `LOG_LEVEL=info`). Key log fields:

| Field | Meaning |
|---|---|
| `email` | OIDC identity being authenticated |
| `user_id` | Ghost ObjectId of the staff user |
| `error` | Error detail when auth fails (passed-through, not hard-blocked) |

Expose gRPC health or wrap with a simple HTTP health endpoint if your platform requires HTTP probes — the current image only exposes the ExtProc gRPC port.
