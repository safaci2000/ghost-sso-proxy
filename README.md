# ghost-sso-proxy

An [Envoy External Processor](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) (ExtProc) gRPC service that bridges OIDC authentication into Ghost admin sessions. When a user completes an OIDC flow via Envoy Gateway, this shim decodes their identity token, verifies they are an active Ghost staff member, and injects a correctly signed `ghost-admin-api-session` cookie so Ghost boots pre-authenticated — no Ghost-side changes required.

## How it works

```
Browser → Envoy Gateway (OIDC filter) → ExtProc (this service) → Ghost
                                              ↕
                                         Ghost MariaDB
```

1. Envoy validates the OIDC ID token and stores it in an `IdToken-<hash>` cookie.
2. Every request to `/ghost` passes through this ExtProc via an `EnvoyExtensionPolicy`.
3. The shim decodes the JWT payload (no re-verification — Envoy already validated it), looks up the user in Ghost's database, creates or reuses a session row, and injects a `Set-Cookie` header containing the signed session cookie that Ghost's express-session layer accepts.

See [docs/architecture.md](docs/architecture.md) for a full walkthrough.

## Quick start — local dev with Ghost + MariaDB

### Option A: devcontainer (recommended)

Requires [Docker](https://docs.docker.com/get-docker/) and one of:
- VS Code + the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension, **or**
- The [`devcontainer` CLI](https://github.com/devcontainers/cli)

```bash
# Clone and open in the devcontainer
git clone https://github.com/csg33k/ghost-sso-proxy
cd ghost-sso-proxy

# VS Code: Cmd/Ctrl+Shift+P → "Dev Containers: Reopen in Container"

# CLI:
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . bash
```

The devcontainer starts MariaDB and Ghost automatically (from `docker-compose.yml`) alongside the Go development shell. Inside the container:

```bash
# Run the proxy against the local Ghost instance
go run ./cmd

# Or compile first
mage build
./bin/ghost-sso-proxy
```

Ghost is reachable at <http://localhost:2368> from your host machine.

### Option B: docker compose (no devcontainer)

Bring up the backing services only, then run the proxy binary on your host:

```bash
# Start Ghost + MariaDB
docker compose up -d

# Wait for Ghost to finish its first-run setup (~30 s)
docker compose logs -f ghost   # Ctrl-C when you see "Ghost is running"

# Copy the example env and fill in your values
cp .env.example .env
# Edit .env — DB_HOST=127.0.0.1 is correct for host→container connectivity

# Run the proxy
go run ./cmd
```

### Wiring the proxy to Ghost — what to configure in Envoy

The proxy exposes a gRPC server on port `8080` (configurable via `GRPC_PORT`). In your Envoy Gateway config you need an `EnvoyExtensionPolicy` pointing at this service and a `SecurityPolicy` with your OIDC provider. See [docs/envoy-wiring.md](docs/envoy-wiring.md) for annotated YAML examples.

## Verifying the integration end-to-end

See [docs/local-testing.md](docs/local-testing.md) for a step-by-step guide that walks through:

- Completing the Ghost setup wizard
- Confirming the proxy can read Ghost's `db_hash`
- Manually injecting a test session cookie to verify signing works
- Using `grpcurl` to send a synthetic ExtProc request

## Running the tests

```bash
# Unit tests (no external dependencies required)
go test ./...

# With race detector
go test -race ./...

# Verbose output
go test -v ./...
```

All tests use only the standard library and in-process mocks — no running database needed.

## Building

```bash
# Local binary
mage build          # → bin/ghost-sso-proxy

# Cross-compile for Linux amd64
mage buildlinux

# Docker image
docker build -t ghost-sso-proxy .

# Release snapshot (no publish)
goreleaser release --snapshot --clean
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DB_HOST` | `mariadb.mariadb.svc.cluster.local` | MariaDB hostname |
| `DB_PORT` | `3306` | MariaDB port |
| `DB_NAME` | `ghost` | Ghost database name |
| `DB_USER` | *(required)* | Database username |
| `DB_PASSWORD` | *(required)* | Database password |
| `GRPC_PORT` | `8080` | Port for the ExtProc gRPC server |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |

Copy `.env.example` to `.env` for local development. In Kubernetes, inject these from a `Secret` as environment variables.

## Project layout

```
cmd/              Entry point — wires adapters and starts gRPC server
config/           Environment-variable configuration
internal/
  core/
    domain/       Pure domain types (User, Session, Identity, errors)
    ports/        Interface contracts (TokenDecoder, UserRepository, SessionStore)
    service/      AuthService — orchestrates the auth flow
  adapters/
    primary/
      extproc/    Envoy ExtProc gRPC server (driving adapter)
    secondary/
      mariadb/    Ghost DB session store + user repository (driven adapter)
      oidctoken/  JWT payload decoder from Envoy's IdToken cookie (driven adapter)
magefiles/        Mage build targets
.devcontainer/    VS Code / devcontainer CLI configuration
docs/             Extended documentation
```

## Release

Releases are built with [GoReleaser](https://goreleaser.com) (see `.goreleaser.yml`). To cut a release:

```bash
git tag v0.x.y
git push origin v0.x.y
# GitHub Actions (or local) picks it up:
goreleaser release --clean
```

Multi-arch Docker images are pushed to `ghcr.io/<owner>/ghost-sso-proxy`.

## Further reading

- [Architecture overview](docs/architecture.md)
- [Local testing guide](docs/local-testing.md)
- [Envoy wiring reference](docs/envoy-wiring.md)
- [Kubernetes deployment](docs/kubernetes-deployment.md)
