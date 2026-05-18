package secondary

import (
	"context"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// TokenDecoder extracts a verified OIDC Identity from request headers.
//
// Envoy Gateway encrypts OIDC tokens with AES-GCM before storing them in
// browser cookies, so IdToken-* cookie values are opaque ciphertext — not raw
// JWTs. When SecurityPolicy.oidc.forwardAccessToken is true, Envoy decrypts the
// access token internally and injects it as "Authorization: Bearer <jwt>" into
// upstream request headers. We decode that header instead.
//
// cookieHeader is kept for fallback / local-dev / unit-test scenarios where a
// raw IdToken-* JWT cookie is available.
type TokenDecoder interface {
	Decode(ctx context.Context, cookieHeader, authorizationHeader string) (*domain.Identity, error)
}
