package domain

// Identity holds the claims extracted from an Envoy-validated OIDC ID token.
// Envoy stores the token in an "IdToken-<hash>" cookie after completing the
// OIDC flow; we decode (but do not re-verify) the JWT payload since Envoy
// already validated the signature against the provider's JWKS.
type Identity struct {
	// Email is the user's email address from the "email" claim.
	Email string
	// Sub is the OIDC subject identifier.
	Sub string
}
