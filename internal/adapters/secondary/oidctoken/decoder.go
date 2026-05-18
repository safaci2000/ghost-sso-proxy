// Package oidctoken implements the driven.TokenDecoder port.
//
// Envoy Gateway encrypts OIDC tokens (IdToken-*, AccessToken-*) with AES-GCM
// before writing them to browser cookies, so those cookie values are opaque
// ciphertext — NOT raw JWTs. We cannot decode them without Envoy's internal
// encryption key.
//
// When SecurityPolicy.oidc.forwardAccessToken is true, Envoy decrypts the
// stored access token and injects it as "Authorization: Bearer <token>" into
// the upstream request (Ghost). However, this header is added AFTER ExtAuth
// runs in the filter chain — ExtAuth does not see it directly.
//
// Instead, extauth/server.go extracts the raw access token from the Envoy
// OAuth2 filter metadata (metadata_context["envoy.filters.http.oauth2"])
// and synthesises a "Bearer <token>" authorization header before calling
// Decode. The decoder then calls the OIDC userinfo endpoint with that token
// to resolve the user's email.
//
// When OIDCUserInfoURL is empty (local dev / unit tests), the decoder falls
// back to local JWT payload decoding — signature verification is intentionally
// skipped because Envoy has already validated the token against the JWKS.
package oidctoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

const idTokenCookiePrefix = "IdToken-"

// Decoder implements driven.TokenDecoder.
type Decoder struct {
	userInfoURL string
	httpClient  *http.Client
}

// NewDecoder constructs a Decoder.
//
// userInfoURL is the OIDC provider's userinfo endpoint
// (e.g. "https://auth.example.com/application/o/envoy-oidc/userinfo/").
// When empty the decoder falls back to local JWT payload decoding, which is
// only suitable for local development with raw (unencrypted) JWTs.
func NewDecoder(userInfoURL string) *Decoder {
	return &Decoder{
		userInfoURL: userInfoURL,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
}

// Decode extracts the OIDC identity from request headers.
//
// Priority:
//  1. Authorization: Bearer <token> — set by extauth/server.go when it finds
//     the access token in Envoy's OAuth2 filter metadata. With a configured
//     userInfoURL the decoder calls the OIDC userinfo endpoint. Without it
//     the decoder attempts local JWT payload decoding (local dev only).
//  2. IdToken-* cookie — fallback for local testing with raw (unencrypted) JWTs.
func (d *Decoder) Decode(ctx context.Context, cookieHeader, authorizationHeader string) (*domain.Identity, error) {
	// Primary path: access token forwarded as Bearer by extauth/server.go.
	if strings.HasPrefix(authorizationHeader, "Bearer ") {
		if d.userInfoURL != "" {
			// Production path: call the OIDC userinfo endpoint.
			return d.fetchUserInfo(ctx, authorizationHeader)
		}
		// Local-dev path: decode the JWT payload locally.
		// In production, Envoy encrypts IdToken-* cookies so local decoding
		// would fail anyway — this branch is only hit during dev/testing.
		jwt := strings.TrimPrefix(authorizationHeader, "Bearer ")
		identity, err := decodeJWTPayload(jwt)
		if err != nil {
			return nil, fmt.Errorf("bearer access token is not a valid JWT: %w", err)
		}
		return identity, nil
	}

	// Fallback: look for a raw IdToken-* cookie (local dev / unit tests).
	if cookieHeader == "" {
		return nil, domain.ErrNoToken
	}
	tokenValue, err := findIDToken(cookieHeader)
	if err != nil {
		return nil, err
	}
	return decodeJWTPayload(tokenValue)
}

// fetchUserInfo calls the OIDC provider's userinfo endpoint with the Bearer
// token and returns the user's identity from the JSON response.
func (d *Decoder) fetchUserInfo(ctx context.Context, authorizationHeader string) (*domain.Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building userinfo request: %v", domain.ErrInvalidToken, err)
	}
	req.Header.Set("Authorization", authorizationHeader)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: calling userinfo endpoint: %v", domain.ErrInvalidToken, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%w: userinfo returned HTTP %d: %s",
			domain.ErrInvalidToken, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("%w: decoding userinfo response: %v", domain.ErrInvalidToken, err)
	}
	if claims.Email == "" {
		return nil, fmt.Errorf("%w: userinfo response missing email claim", domain.ErrInvalidToken)
	}

	return &domain.Identity{
		Email: claims.Email,
		Sub:   claims.Sub,
	}, nil
}

// findIDToken parses the Cookie header and returns the value of the first
// cookie whose name starts with "IdToken-".
func findIDToken(cookieHeader string) (string, error) {
	h := http.Header{}
	h.Add("Cookie", cookieHeader)
	req := &http.Request{Header: h}

	for _, cookie := range req.Cookies() {
		if strings.HasPrefix(cookie.Name, idTokenCookiePrefix) {
			return cookie.Value, nil
		}
	}
	return "", domain.ErrNoToken
}

// decodeJWTPayload base64url-decodes the middle segment of a JWT and
// extracts the email and sub claims without verifying the signature.
func decodeJWTPayload(token string) (*domain.Identity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 segments, got %d", domain.ErrInvalidToken, len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode: %v", domain.ErrInvalidToken, err)
	}

	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: json unmarshal: %v", domain.ErrInvalidToken, err)
	}
	if claims.Email == "" {
		return nil, fmt.Errorf("%w: email claim is absent", domain.ErrInvalidToken)
	}

	return &domain.Identity{
		Email: claims.Email,
		Sub:   claims.Sub,
	}, nil
}
