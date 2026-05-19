package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
	"github.com/safaci2000/ghost-sso-proxy/internal/core/ports/secondary"
)

const ghostSessionCookieName = "ghost-admin-api-session"

// AuthService implements primary.AuthService. It orchestrates the two secondary
// ports: verify staff membership → ensure a session exists.
// Identity resolution (email) is handled upstream by the ExtAuth adapter.
type AuthService struct {
	users    secondary.UserRepository
	sessions secondary.SessionStore
	logger   *slog.Logger
}

// New constructs an AuthService wired with the provided adapters.
func New(
	users secondary.UserRepository,
	sessions secondary.SessionStore,
	logger *slog.Logger,
) *AuthService {
	return &AuthService{
		users:    users,
		sessions: sessions,
		logger:   logger,
	}
}

// EnsureSession implements primary.AuthService.
func (s *AuthService) EnsureSession(ctx context.Context, cookieHeader, email string) (string, error) {
	// Fast path: ghost session cookie already present, nothing to do.
	if hasGhostSessionCookie(cookieHeader) {
		s.logger.DebugContext(ctx, "ghost-admin-api-session cookie present, passing through")
		return "", nil
	}

	s.logger.InfoContext(ctx, "no ghost session cookie found, verifying staff membership",
		slog.String("email", email))

	// Verify the identity maps to an active Ghost staff user.
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return "", fmt.Errorf("%w: %s", domain.ErrUnauthorized, email)
		}
		return "", fmt.Errorf("user repository: %w", err)
	}
	if !user.IsActive() {
		return "", fmt.Errorf("%w: status=%s", domain.ErrUnauthorized, user.Status)
	}

	// Reuse an existing DB session for this user if one already exists —
	// avoids creating duplicate rows on concurrent or rapid requests.
	existing, err := s.sessions.FindByUserID(ctx, user.ID)
	if err != nil {
		return "", fmt.Errorf("session store lookup: %w", err)
	}
	if existing != nil {
		s.logger.InfoContext(ctx, "reusing existing ghost session",
			slog.String("user_id", user.ID))
		// At debug level emit the full signed value so operators can manually
		// paste it into browser DevTools (Application → Cookies) to verify
		// that Ghost accepts it independently of Envoy's cookie forwarding.
		s.logger.DebugContext(ctx, "signed cookie for manual browser test",
			slog.String("cookie_value", existing.SignedCookieValue))
		return existing.SignedCookieValue, nil
	}

	// Create a fresh session and persist it to the Ghost DB.
	session, err := s.sessions.Create(ctx, user.ID)
	if err != nil {
		return "", fmt.Errorf("session store create: %w", err)
	}

	s.logger.InfoContext(ctx, "created ghost admin session",
		slog.String("user_id", user.ID),
		slog.String("email", email))
	s.logger.DebugContext(ctx, "signed cookie for manual browser test",
		slog.String("cookie_value", session.SignedCookieValue))

	return session.SignedCookieValue, nil
}

// hasGhostSessionCookie reports whether the Cookie header contains a ghost-admin-api-session entry.
func hasGhostSessionCookie(cookieHeader string) bool {
	if cookieHeader == "" {
		return false
	}
	h := http.Header{}
	h.Add("Cookie", cookieHeader)
	req := &http.Request{Header: h}
	_, err := req.Cookie(ghostSessionCookieName)
	return err == nil
}
