package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// ─── Mocks ────────────────────────────────────────────────────────────────────

type mockUserRepo struct {
	user *domain.User
	err  error
}

func (m *mockUserRepo) FindByEmail(_ context.Context, _ string) (*domain.User, error) {
	return m.user, m.err
}

type mockSessionStore struct {
	existing    *domain.Session
	findErr     error
	created     *domain.Session
	createErr   error
	createCalls int
}

func (m *mockSessionStore) FindByUserID(_ context.Context, _ string) (*domain.Session, error) {
	return m.existing, m.findErr
}

func (m *mockSessionStore) Create(_ context.Context, _ string) (*domain.Session, error) {
	m.createCalls++
	return m.created, m.createErr
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func newTestService(users *mockUserRepo, sess *mockSessionStore) *AuthService {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return New(users, sess, logger)
}

const (
	ghostSessionCookie = "ghost-admin-api-session=s:abc.xyz"
	testEmail          = "user@example.com"
	noCookie           = "other=val"
)

// ─── Test: fast-path (ghost session already present) ──────────────────────────

func TestEnsureSession_FastPath(t *testing.T) {
	svc := newTestService(&mockUserRepo{}, &mockSessionStore{})

	got, err := svc.EnsureSession(context.Background(), ghostSessionCookie+"; other=stuff", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty cookie on fast path, got %q", got)
	}
}

// ─── Test: empty email → unauthorized ────────────────────────────────────────

func TestEnsureSession_EmptyEmail(t *testing.T) {
	svc := newTestService(
		&mockUserRepo{err: domain.ErrUserNotFound},
		&mockSessionStore{},
	)

	_, err := svc.EnsureSession(context.Background(), noCookie, "")
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for empty email, got %v", err)
	}
}

// ─── Test: user not found → unauthorized ─────────────────────────────────────

func TestEnsureSession_UserNotFound(t *testing.T) {
	svc := newTestService(
		&mockUserRepo{err: domain.ErrUserNotFound},
		&mockSessionStore{},
	)

	_, err := svc.EnsureSession(context.Background(), noCookie, "unknown@example.com")
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// ─── Test: user found but inactive ───────────────────────────────────────────

func TestEnsureSession_UserInactive(t *testing.T) {
	svc := newTestService(
		&mockUserRepo{user: &domain.User{ID: "abc", Email: testEmail, Status: "suspended"}},
		&mockSessionStore{},
	)

	_, err := svc.EnsureSession(context.Background(), noCookie, testEmail)
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// ─── Test: reuse existing session ────────────────────────────────────────────

func TestEnsureSession_ReuseExisting(t *testing.T) {
	existingSession := &domain.Session{
		SessionID:         "existingID",
		SignedCookieValue: "s:existingID.hmac",
		UserID:            "user001",
		CreatedAt:         time.Now(),
	}
	store := &mockSessionStore{existing: existingSession}
	svc := newTestService(
		&mockUserRepo{user: &domain.User{ID: "user001", Email: testEmail, Status: "active"}},
		store,
	)

	got, err := svc.EnsureSession(context.Background(), noCookie, testEmail)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != existingSession.SignedCookieValue {
		t.Fatalf("expected %q, got %q", existingSession.SignedCookieValue, got)
	}
	if store.createCalls != 0 {
		t.Fatal("Create should not have been called when a session already exists")
	}
}

// ─── Test: create new session ─────────────────────────────────────────────────

func TestEnsureSession_CreateNew(t *testing.T) {
	newSession := &domain.Session{
		SessionID:         "newID123",
		SignedCookieValue: "s:newID123.hmac",
		UserID:            "user001",
		CreatedAt:         time.Now(),
	}
	store := &mockSessionStore{existing: nil, created: newSession}
	svc := newTestService(
		&mockUserRepo{user: &domain.User{ID: "user001", Email: testEmail, Status: "active"}},
		store,
	)

	got, err := svc.EnsureSession(context.Background(), noCookie, testEmail)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != newSession.SignedCookieValue {
		t.Fatalf("expected %q, got %q", newSession.SignedCookieValue, got)
	}
	if store.createCalls != 1 {
		t.Fatalf("expected 1 Create call, got %d", store.createCalls)
	}
}

// ─── Test: session store create error ────────────────────────────────────────

func TestEnsureSession_CreateError(t *testing.T) {
	dbErr := errors.New("db connection lost")
	store := &mockSessionStore{existing: nil, createErr: dbErr}
	svc := newTestService(
		&mockUserRepo{user: &domain.User{ID: "user001", Email: testEmail, Status: "active"}},
		store,
	)

	_, err := svc.EnsureSession(context.Background(), noCookie, testEmail)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ─── Test: hasGhostSessionCookie ─────────────────────────────────────────────

func TestHasGhostSessionCookie(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{"empty", "", false},
		{"other only", "session=abc; foo=bar", false},
		{"ghost present", "ghost-admin-api-session=s:id.sig; other=x", true},
		{"ghost only", "ghost-admin-api-session=s:id.sig", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasGhostSessionCookie(tc.header); got != tc.want {
				t.Fatalf("hasGhostSessionCookie(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}
