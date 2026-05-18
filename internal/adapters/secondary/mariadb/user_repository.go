package mariadb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// UserRepository implements driven.UserRepository against the Ghost `users` table.
//
// Ghost's `users` table contains only staff members (Administrators, Editors,
// Authors, Contributors). Newsletter subscribers/members live in a separate
// `members` table and will never appear here, so a simple email lookup is a
// sufficient staff-membership check — no roles join required.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository constructs a UserRepository sharing the provided connection pool.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// FindByEmail implements driven.UserRepository.
// Returns domain.ErrUserNotFound when no matching row exists.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, email, status FROM users WHERE email = ? LIMIT 1`,
		email)

	var u domain.User
	if err := row.Scan(&u.ID, &u.Email, &u.Status); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("mariadb: querying users: %w", err)
	}
	return &u, nil
}
