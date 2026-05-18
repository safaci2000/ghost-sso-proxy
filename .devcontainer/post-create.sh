#!/usr/bin/env bash
# post-create.sh — runs once after the devcontainer is first created.
# Installs project tooling and pre-warms the Go module cache.
set -euo pipefail

echo "==> Downloading Go modules..."
cd /workspace
go mod download

echo "==> Installing Mage (build tool)..."
go install github.com/magefile/mage@latest

echo "==> Installing GoReleaser..."
GORELEASER_VERSION="v2.9.0"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac
curl -sSfL \
  "https://github.com/goreleaser/goreleaser/releases/download/${GORELEASER_VERSION}/goreleaser_${OS}_${ARCH}.tar.gz" \
  | tar -xz -C /usr/local/bin goreleaser
chmod +x /usr/local/bin/goreleaser

echo "==> Installing golangci-lint..."
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
  | sh -s -- -b /usr/local/bin latest

echo "==> Verifying toolchain..."
go version
mage --version
goreleaser --version
golangci-lint --version

echo ""
echo "✓ Devcontainer ready. Quick-start:"
echo "  go run ./cmd            # run the proxy (needs Ghost + MariaDB running)"
echo "  go test ./...           # run all unit tests"
echo "  mage build              # compile → bin/ghost-sso-proxy"
echo "  goreleaser check        # validate .goreleaser.yml"
echo ""
echo "  Ghost is available at: http://localhost:2368"
echo "  proxy gRPC listens on: :8080"
