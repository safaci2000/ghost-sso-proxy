package secondary

import "context"

// ForwardAuthChecker validates whether the current browser session is
// authenticated via an external identity provider using the forward auth
// pattern. The concrete implementation calls the Authentik forward auth
// endpoint, forwarding the browser's Cookie header so Authentik can inspect
// its own proxy session cookie.
//
// This port is driven by the ExtAuth primary adapter, which calls it before
// invoking AuthService.EnsureSession so that identity resolution is handled
// at the adapter boundary and the core service receives a plain email string.
type ForwardAuthChecker interface {
	// Check forwards the browser's Cookie header to the identity provider's
	// forward auth endpoint along with the original request's host, protocol,
	// and URI for the provider to construct accurate redirect-back URLs.
	//
	// Returns (email, "", nil, nil) when the user is authenticated.
	// Returns ("", redirectURL, setCookies, nil) when the user must log in —
	// the caller should redirect the browser to redirectURL and forward any
	// setCookies (e.g. Authentik PKCE state cookies) so the OAuth2 callback
	// can complete.
	// Returns ("", "", nil, err) on any network or protocol error — the caller
	// should fail-open.
	Check(ctx context.Context, cookieHeader, host, proto, uri string) (email, redirectURL string, setCookies []string, err error)
}
