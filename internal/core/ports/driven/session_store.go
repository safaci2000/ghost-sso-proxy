package driven

import (
	"context"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// SessionStore reads and writes Ghost admin sessions in the database.
// Ghost stores sessions in the `sessions` table; the cookie value is an
// express-session signed ID ("s:<id>.<hmac>") where the HMAC key is the
// Ghost admin_session_secret setting read from the `settings` table at startup.
// (db_hash is used for password-reset tokens, not session cookie signing.)
type SessionStore interface {
	// FindByUserID returns the most recent existing session for a Ghost user ID,
	// or (nil, nil) when none exists.
	FindByUserID(ctx context.Context, userID string) (*domain.Session, error)

	// Create inserts a new session for the given Ghost user ID and returns it.
	// The returned Session includes the SignedCookieValue ready to set as a cookie.
	Create(ctx context.Context, userID string) (*domain.Session, error)
}
