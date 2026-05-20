package driven

import (
	"context"

	"github.com/csg33k/ghost-sso-proxy/internal/core/domain"
)

// UserRepository looks up Ghost staff users. The concrete implementation calls
// the Ghost Admin API (read-only) using a signed JWT derived from an Admin API key.
type UserRepository interface {
	// FindByEmail returns the Ghost staff user with the given email address.
	// Returns domain.ErrUserNotFound when no such user exists.
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
}
