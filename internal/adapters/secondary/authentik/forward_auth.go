// Package authentik implements a client for Authentik's forward auth endpoint.
//
// In forward auth mode, Authentik's embedded outpost (proxyv2) acts as the
// identity layer. Instead of Envoy running an internal oauth2 filter, the
// ExtAuth adapter calls this client directly. The client forwards the browser's
// Cookie header so Authentik can validate its own proxy session cookie and
// return the authenticated user's email.
//
// The correct endpoint for Authentik 2026.x proxyv2 is:
//
//	https://auth.example.com/outpost.goauthentik.io/auth/traefik
//
// (The per-application path /auth/application/<slug>/ was removed in 2026.x.)
//
// Request flow:
//
//  1. ExtAuth calls Client.Check with the browser's Cookie header and the
//     original request's host/proto/uri (sent as X-Forwarded-* headers).
//  2. Authentik validates its proxy session cookie.
//     — HTTP 200 + X-Authentik-Email: authenticated; return email.
//     — HTTP 302 + Location: user not logged in; Authentik starts an OAuth2
//       PKCE flow and sets authentik_proxy_* state cookies. Return the redirect
//       URL and those Set-Cookie values so ExtAuth can forward them to the
//       browser (without the PKCE state cookie the callback will fail).
//     — Any other status: treat as an error; caller should fail-open.
package authentik

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client calls the Authentik forward auth endpoint.
type Client struct {
	endpointURL string
	httpClient  *http.Client
}

// NewClient constructs a Client for the given Authentik forward auth endpoint URL.
// Example: "https://auth.example.com/outpost.goauthentik.io/auth/traefik"
// When endpointURL is empty every Check call returns an error (fail-open in the caller).
func NewClient(endpointURL string) *Client {
	return &Client{
		endpointURL: endpointURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			// Do not follow redirects — we need to inspect the 302 ourselves.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Check forwards the browser's Cookie header to Authentik's forward auth endpoint.
//
// Returns (email, "", nil, nil) when the user is authenticated (HTTP 200).
// Returns ("", redirectURL, setCookies, nil) when the user is not logged in
// (HTTP 302). setCookies contains any Set-Cookie values from the response —
// Authentik sets authentik_proxy_* PKCE state cookies that must reach the
// browser or the OAuth2 callback will fail with "invalid state".
// Returns ("", "", nil, err) on any other response or network error.
func (c *Client) Check(ctx context.Context, cookieHeader, host, proto, uri string) (email, redirectURL string, setCookies []string, err error) {
	if c.endpointURL == "" {
		return "", "", nil, fmt.Errorf("authentik forward auth: endpoint URL is not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpointURL, nil)
	if err != nil {
		return "", "", nil, fmt.Errorf("authentik forward auth: building request: %w", err)
	}

	if cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Proto", proto)
	req.Header.Set("X-Forwarded-Uri", uri)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", nil, fmt.Errorf("authentik forward auth: request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		email = resp.Header.Get("X-Authentik-Email")
		if email == "" {
			return "", "", nil, fmt.Errorf("authentik forward auth: 200 response missing X-Authentik-Email header")
		}
		return email, "", nil, nil

	case http.StatusFound:
		location := resp.Header.Get("Location")
		if location == "" {
			return "", "", nil, fmt.Errorf("authentik forward auth: 302 response missing Location header")
		}
		// Collect all Set-Cookie headers so the caller can forward the PKCE
		// state cookies to the browser (required for the OAuth2 callback).
		cookies := resp.Header["Set-Cookie"]
		return "", location, cookies, nil

	default:
		return "", "", nil, fmt.Errorf("authentik forward auth: unexpected HTTP status %d", resp.StatusCode)
	}
}
