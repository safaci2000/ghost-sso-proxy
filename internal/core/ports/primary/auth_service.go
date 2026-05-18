package primary

import (
	"context"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// AuthService is the primary port — the interface the ExtProc adapter drives.
// It inspects incoming request headers and decides whether a Ghost admin session
// cookie needs to be created and injected into the response.
type AuthService interface {
	// EnsureSession inspects the Envoy request headers. If a valid
	// ghost-admin-api-session cookie is already present it returns ("", nil)
	// signalling no action is needed. Otherwise it decodes the OIDC identity,
	// verifies the user is active Ghost staff, and returns the signed cookie
	// value to be injected via Set-Cookie in the response phase.
	EnsureSession(ctx context.Context, headers []*corev3.HeaderValue) (signedCookieValue string, err error)
}
