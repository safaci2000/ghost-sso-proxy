// Package mariadb implements the driven.SessionStore port by reading and writing
// directly to Ghost's MySQL/MariaDB `sessions` table.
//
// Session signing
// ---------------
// Ghost uses express-session with cookie signing enabled. The cookie sent to
// the browser is: "s:<session_id>.<base64(HMAC-SHA256(session_id, secret))>"
// where "secret" is the value of the `admin_session_secret` row in Ghost's
// `settings` table — NOT `db_hash` (which is only used for password-reset tokens).
// We read that value once at startup and use it to produce correctly-signed cookies.
//
// Session ID format
// -----------------
// express-session (via uid-safe) generates a 32-character URL-safe base64 string
// from 24 random bytes. We match that format exactly.
//
// Object ID format
// ----------------
// Ghost's `id` column uses a MongoDB-style 24-character hex ObjectId:
// 4 bytes big-endian unix timestamp + 8 bytes random.
package mariadb

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// SessionStore implements driven.SessionStore against MariaDB.
type SessionStore struct {
	db            *sql.DB
	dbHash        string // Ghost's admin_session_secret; used as the express-session HMAC signing key
	sessionMaxAge int    // session lifetime in days; drives session_data expiry and FindByUserID cutoff
}

// Connect opens a shared connection pool and pings the DB.
// The returned *sql.DB is passed to both NewSessionStore and NewUserRepository
// so the two adapters share one pool.
func Connect(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("mariadb: opening connection: %w", err)
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("mariadb: ping failed: %w", err)
	}
	return db, nil
}

// NewSessionStore constructs a SessionStore from an existing connection pool.
// It reads the Ghost admin_session_secret setting once at startup — this is the
// secret that Ghost passes to express-session for cookie HMAC signing, and is
// stable for the lifetime of the instance.
//
// sessionMaxAgeDays controls the session lifetime written into session_data and
// the cutoff used by FindByUserID to skip expired sessions. Pass
// cfg.SessionMaxAgeDays so this tracks the SESSION_MAX_AGE_DAYS env var.
//
// Note: db_hash is used for password-reset tokens and internal hashing, NOT for
// session cookie signing. The express-session secret is admin_session_secret.
func NewSessionStore(db *sql.DB, sessionMaxAgeDays int) (*SessionStore, error) {
	var sessionSecret string
	err := db.QueryRow("SELECT `value` FROM `settings` WHERE `key` = 'admin_session_secret' LIMIT 1").Scan(&sessionSecret)
	if err != nil {
		return nil, fmt.Errorf("mariadb: reading admin_session_secret from settings: %w", err)
	}
	if sessionSecret == "" {
		return nil, fmt.Errorf("mariadb: admin_session_secret setting is empty")
	}
	// Ghost stores settings values as JSON-encoded strings in the database
	// (e.g. the raw column bytes are `"abc123"` with surrounding double-quotes).
	// Unwrap the JSON layer so the HMAC key matches what Ghost uses internally.
	rawSecret := sessionSecret
	jsonDecoded := false
	var unquoted string
	if err := json.Unmarshal([]byte(sessionSecret), &unquoted); err == nil && unquoted != "" {
		sessionSecret = unquoted
		jsonDecoded = true
	}

	// Emit a startup log so operators can verify the secret is being read correctly.
	// Shows the first/last 4 chars — enough to cross-check against the DB without
	// leaking the full value.
	slog.Info("admin_session_secret loaded",
		"json_decoded", jsonDecoded,
		"raw_len", len(rawSecret),
		"final_len", len(sessionSecret),
		"raw_head", safeHead(rawSecret, 4),
		"raw_tail", safeTail(rawSecret, 4),
		"decoded_head", safeHead(sessionSecret, 4),
		"decoded_tail", safeTail(sessionSecret, 4),
	)

	return &SessionStore{db: db, dbHash: sessionSecret, sessionMaxAge: sessionMaxAgeDays}, nil
}

// FindByUserID implements driven.SessionStore.
// Returns the most recent non-expired session for the given Ghost user ID, or
// (nil, nil) when none exists. Sessions older than sessionMaxAgeDays are
// excluded — their session_data.cookie.expires is already in the past, so
// Ghost would reject them and the browser would see an empty admin page.
//
// When a session is found it is immediately refreshed: session_data is rebuilt
// with current timestamps and verified:true, and updated_at is bumped. This
// mirrors what Ghost's own session middleware does on every request and ensures
// that a session row written by an older version of this code (which may have
// been missing verified:true or had a stale expiry) never causes a Ghost 403.
func (s *SessionStore) FindByUserID(ctx context.Context, userID string) (*domain.Session, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -s.sessionMaxAge)
	row := s.db.QueryRowContext(ctx,
		`SELECT session_id, user_id, created_at
		   FROM sessions
		  WHERE user_id = ?
		    AND created_at >= ?
		  ORDER BY created_at DESC
		  LIMIT 1`,
		userID, cutoff)

	var sess domain.Session
	var createdAt time.Time
	if err := row.Scan(&sess.SessionID, &sess.UserID, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("mariadb: querying sessions: %w", err)
	}
	sess.CreatedAt = createdAt

	// Refresh session_data so the row always has up-to-date fields regardless
	// of how or when the row was originally written.
	sessionData, err := buildSessionData(userID, s.sessionMaxAge)
	if err != nil {
		return nil, fmt.Errorf("mariadb: refreshing session_data: %w", err)
	}
	now := time.Now().UTC()
	if _, err = s.db.ExecContext(ctx,
		`UPDATE sessions SET session_data = ?, updated_at = ? WHERE session_id = ?`,
		sessionData, now, sess.SessionID); err != nil {
		return nil, fmt.Errorf("mariadb: updating session_data: %w", err)
	}

	sess.SignedCookieValue = signCookie(sess.SessionID, s.dbHash)
	return &sess, nil
}

// Create implements driven.SessionStore.
// Generates a new session ID, inserts the row, and returns the Session with
// a correctly-signed cookie value ready for the Set-Cookie header.
func (s *SessionStore) Create(ctx context.Context, userID string) (*domain.Session, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("mariadb: generating session ID: %w", err)
	}
	objectID, err := generateObjectID()
	if err != nil {
		return nil, fmt.Errorf("mariadb: generating object ID: %w", err)
	}
	sessionData, err := buildSessionData(userID, s.sessionMaxAge)
	if err != nil {
		return nil, fmt.Errorf("mariadb: building session_data: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, session_id, user_id, session_data, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		objectID, sessionID, userID, sessionData, now, now)
	if err != nil {
		return nil, fmt.Errorf("mariadb: inserting session: %w", err)
	}

	return &domain.Session{
		SessionID:         sessionID,
		SignedCookieValue: signCookie(sessionID, s.dbHash),
		UserID:            userID,
		CreatedAt:         now,
	}, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// signCookie replicates express's cookie-signature.sign():
//
//	"s:" + val + "." + base64(HMAC-SHA256(val, secret)).trimRight("=")
func signCookie(sessionID, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sessionID))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	sig = strings.TrimRight(sig, "=")
	return "s:" + sessionID + "." + sig
}

// generateSessionID produces a 32-character URL-safe base64 string from 24
// crypto-random bytes, matching uid-safe's output format used by express-session.
func generateSessionID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateObjectID produces a Ghost-compatible 24-character hex ObjectId:
// 4 bytes big-endian unix timestamp + 8 bytes random = 12 bytes total.
func generateObjectID() (string, error) {
	b := make([]byte, 12)
	binary.BigEndian.PutUint32(b[:4], uint32(time.Now().Unix()))
	if _, err := rand.Read(b[4:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ghostSessionData mirrors the JSON blob that Ghost's express-ghost-session
// package serialises into the session_data column. Field names and values must
// match exactly what Ghost writes; discrepancies (e.g. missing "verified")
// cause Ghost's admin API to reject the session with a 403.
//
// Observed from a real Ghost 6.x session row:
//
//	{"cookie":{"originalMaxAge":15552000000,"expires":"2026-11-13T23:28:01.011Z",
//	 "secure":true,"httpOnly":true,"path":"/ghost","sameSite":"none"},
//	 "user_id":"...","origin":"https://example.com","user_agent":"...","ip":"...",
//	 "verified":true}
type ghostSessionData struct {
	Cookie   ghostCookieMeta `json:"cookie"`
	UserID   string          `json:"user_id"`
	Verified bool            `json:"verified"`
	// Origin, UserAgent, and IP are populated by Ghost's own session handler when
	// a user logs in interactively. We cannot replicate them without access to the
	// original HTTP request context in this adapter. Ghost currently does not
	// enforce their presence for API authorisation, but they appear in every
	// Ghost-created row so we set them to empty strings rather than omitting them,
	// to stay as close to the expected schema as possible.
	Origin    string `json:"origin"`
	UserAgent string `json:"user_agent"`
	IP        string `json:"ip"`
}

// ghostCookieMeta matches the "cookie" sub-object in Ghost's session_data JSON.
// originalMaxAge is 180 days in milliseconds (15552000000), matching Ghost's
// default maxAge. expires is an ISO-8601 string (not a Unix timestamp).
type ghostCookieMeta struct {
	OriginalMaxAge int64  `json:"originalMaxAge"` // milliseconds; 0 = browser session
	Expires        string `json:"expires"`        // ISO-8601 UTC string
	Secure         bool   `json:"secure"`
	HTTPOnly       bool   `json:"httpOnly"`
	Path           string `json:"path"`
	SameSite       string `json:"sameSite"`
}

// defaultSessionMaxAgeDays is used only in package-level tests that call
// buildSessionData directly. Production code always passes sessionMaxAge via
// the SessionStore field (seeded from cfg.SessionMaxAgeDays).
const defaultSessionMaxAgeDays = 180

// safeHead returns the first n runes of s (or all of s if shorter).
func safeHead(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// safeTail returns the last n runes of s (or all of s if shorter).
func safeTail(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

func buildSessionData(userID string, maxAgeDays int) (string, error) {
	maxAgeMs := int64(maxAgeDays * 24 * 60 * 60 * 1000)
	expires := time.Now().UTC().Add(time.Duration(maxAgeDays) * 24 * time.Hour)

	data := ghostSessionData{
		Cookie: ghostCookieMeta{
			OriginalMaxAge: maxAgeMs,
			Expires:        expires.Format(time.RFC3339Nano),
			Secure:         true,
			HTTPOnly:       true,
			Path:           "/ghost",
			// Ghost uses "none" so the cookie is sent on cross-origin requests
			// (e.g. the Ghost admin SPA calling the admin API).
			// "none" requires Secure=true, which we always set.
			SameSite: "none",
		},
		UserID:   userID,
		Verified: true,
		// Origin, UserAgent, and IP are unknown at session-creation time in this
		// adapter. Empty strings are stored so the JSON structure stays consistent
		// with what Ghost writes; Ghost does not validate these fields on auth.
		Origin:    "",
		UserAgent: "",
		IP:        "",
	}
	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
