package driven

import (
	"context"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// TokenDecoder extracts a verified OIDC Identity from the raw Cookie header
// value forwarded by Envoy. Envoy stores the validated ID token in a cookie
// named "IdToken-<crc32hash>"; the decoder finds it by prefix and decodes
// the JWT payload without re-verifying the signature.
type TokenDecoder interface {
	Decode(ctx context.Context, cookieHeader string) (*domain.Identity, error)
}
