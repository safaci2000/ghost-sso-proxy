// Package oidctoken implements the driven.TokenDecoder port by finding
// Envoy's "IdToken-<hash>" cookie and decoding the JWT payload.
//
// Envoy Gateway's SecurityPolicy OIDC filter stores the validated ID token in
// a cookie whose name is "IdToken-" followed by a CRC32 hash of the OIDC
// provider configuration. Because the hash is deterministic per-deployment but
// not known at compile time, we locate the cookie by prefix match rather than
// exact name.
//
// Signature verification is intentionally skipped: Envoy has already validated
// the token against the provider's JWKS before our ExtProc is invoked.
package oidctoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

const idTokenCookiePrefix = "IdToken-"

// Decoder implements driven.TokenDecoder.
type Decoder struct{}

// NewDecoder constructs a Decoder.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decode finds the IdToken-* cookie in the raw Cookie header, base64url-decodes
// the JWT payload segment, and extracts the email and sub claims.
func (d *Decoder) Decode(_ context.Context, cookieHeader string) (*domain.Identity, error) {
	if cookieHeader == "" {
		return nil, domain.ErrNoToken
	}

	tokenValue, err := findIDToken(cookieHeader)
	if err != nil {
		return nil, err
	}

	return decodeJWTPayload(tokenValue)
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
