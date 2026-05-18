package domain

import "time"

// Session represents a Ghost admin session that has been created in the database.
type Session struct {
	// SessionID is the raw session identifier stored in the sessions table and
	// used as the value of the ghost-admin-api-session cookie (unsigned).
	SessionID string
	// SignedCookieValue is the express-session signed form: "s:<id>.<hmac>"
	// This is what the browser stores and Ghost validates.
	SignedCookieValue string
	// UserID is the Ghost ObjectId of the staff user this session belongs to.
	UserID string
	// CreatedAt is when the session row was inserted.
	CreatedAt time.Time
}
