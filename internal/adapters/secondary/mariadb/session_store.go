// Package mariadb implements the driven.SessionStore port by reading and writing
// directly to Ghost's MySQL/MariaDB `sessions` table.
//
// Session signing
// ---------------
// Ghost uses express-session with cookie signing enabled. The cookie sent to
// the browser is: "s:<session_id>.<base64(HMAC-SHA256(session_id, secret))>"
// where "secret" is the value of the `db_hash` row in Ghost's `settings` table.
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
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// SessionStore implements driven.SessionStore against MariaDB.
type SessionStore struct {
	db     *sql.DB
	dbHash string // Ghost's db_hash setting; used as the express-session signing secret
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
// It reads the Ghost db_hash setting once at startup — this value is the
// express-session HMAC signing secret and is stable for the lifetime of the instance.
func NewSessionStore(db *sql.DB) (*SessionStore, error) {
	var dbHash string
	err := db.QueryRow("SELECT `value` FROM `settings` WHERE `key` = 'db_hash' LIMIT 1").Scan(&dbHash)
	if err != nil {
		return nil, fmt.Errorf("mariadb: reading db_hash from settings: %w", err)
	}
	if dbHash == "" {
		return nil, fmt.Errorf("mariadb: db_hash setting is empty")
	}
	return &SessionStore{db: db, dbHash: dbHash}, nil
}

// FindByUserID implements driven.SessionStore.
// Returns the most recent session for the given Ghost user ID, or (nil, nil)
// when none exists.
func (s *SessionStore) FindByUserID(ctx context.Context, userID string) (*domain.Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT session_id, user_id, created_at
		   FROM sessions
		  WHERE user_id = ?
		  ORDER BY created_at DESC
		  LIMIT 1`,
		userID)

	var sess domain.Session
	var createdAt time.Time
	if err := row.Scan(&sess.SessionID, &sess.UserID, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("mariadb: querying sessions: %w", err)
	}
	sess.CreatedAt = createdAt
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
	sessionData, err := buildSessionData(userID)
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

// ghostSessionData mirrors the JSON blob that express-session serialises to the store.
type ghostSessionData struct {
	Cookie ghostCookieMeta `json:"cookie"`
	UserID string          `json:"user_id"`
}

type ghostCookieMeta struct {
	OriginalMaxAge *int64 `json:"originalMaxAge"` // nil = browser session cookie
	Expires        *int64 `json:"expires"`        // nil = no explicit expiry
	Secure         bool   `json:"secure"`
	HTTPOnly       bool   `json:"httpOnly"`
	Path           string `json:"path"`
	SameSite       string `json:"sameSite"`
}

func buildSessionData(userID string) (string, error) {
	data := ghostSessionData{
		Cookie: ghostCookieMeta{
			OriginalMaxAge: nil,
			Expires:        nil,
			Secure:         true,
			HTTPOnly:       true,
			Path:           "/ghost",
			SameSite:       "lax",
		},
		UserID: userID,
	}
	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
