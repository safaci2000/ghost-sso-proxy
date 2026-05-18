package secondary

import (
	"context"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// UserRepository looks up Ghost staff users. The concrete implementation
// queries Ghost's `users` table directly — Ghost staff are the only users
// in that table; newsletter members live in a separate `members` table.
type UserRepository interface {
	// FindByEmail returns the Ghost staff user with the given email address.
	// Returns domain.ErrUserNotFound when no such user exists.
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
}
