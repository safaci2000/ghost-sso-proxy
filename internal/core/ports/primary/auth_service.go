package primary

import "context"

// AuthService is the primary port — the interface the ExtAuth adapter drives.
// It inspects incoming request headers and decides whether a Ghost admin session
// cookie needs to be created and injected into the response.
type AuthService interface {
	// EnsureSession inspects the cookie and authorization headers forwarded by
	// Envoy. If a valid ghost-admin-api-session cookie is already present it
	// returns ("", nil) signalling no action is needed. Otherwise it decodes the
	// OIDC identity, verifies the user is active Ghost staff, and returns the
	// signed cookie value to be injected via Set-Cookie in the response.
	EnsureSession(ctx context.Context, cookieHeader, authHeader string) (signedCookieValue string, err error)
}
