package primary

import "context"

// AuthService is the primary port — the interface the ExtAuth adapter drives.
// It inspects incoming request headers and decides whether a Ghost admin session
// cookie needs to be created and injected into the response.
type AuthService interface {
	// EnsureSession checks whether a Ghost admin session cookie is already
	// present (fast path: returns "", nil) or creates one for the given email.
	// The caller (the ExtAuth adapter) is responsible for resolving the user's
	// email before invoking this method — e.g. via Authentik forward auth.
	EnsureSession(ctx context.Context, cookieHeader, email string) (signedCookieValue string, err error)
}
