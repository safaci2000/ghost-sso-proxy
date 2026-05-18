package mariadb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// ─── signCookie ───────────────────────────────────────────────────────────────

func TestSignCookie_Format(t *testing.T) {
	signed := signCookie("mySessionID", "mysecret")
	if !strings.HasPrefix(signed, "s:mySessionID.") {
		t.Fatalf("expected prefix s:mySessionID., got %q", signed)
	}
}

func TestSignCookie_HMACCorrectness(t *testing.T) {
	sessionID := "abc123def456"
	secret := "ghost-db-hash-value"

	signed := signCookie(sessionID, secret)

	// Re-derive HMAC and verify it matches the signature portion.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sessionID))
	expected := strings.TrimRight(base64.StdEncoding.EncodeToString(mac.Sum(nil)), "=")

	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("expected exactly one dot in signed cookie, got %q", signed)
	}
	sigPart := parts[1]
	if sigPart != expected {
		t.Fatalf("HMAC mismatch:\n  got  %q\n  want %q", sigPart, expected)
	}
}

func TestSignCookie_NoPaddingChars(t *testing.T) {
	// base64 padding ("=") must be stripped so the cookie value is safe.
	// Use a session ID whose HMAC happens to produce trailing "="; we verify
	// the output never contains "=" by checking a range of inputs.
	for _, sid := range []string{"a", "ab", "abc", "abcd", "abcde", "abcdef"} {
		signed := signCookie(sid, "secret")
		if strings.Contains(signed, "=") {
			t.Fatalf("signCookie(%q) contains '=': %q", sid, signed)
		}
	}
}

func TestSignCookie_DifferentSecretsDifferentSigs(t *testing.T) {
	sig1 := signCookie("session", "secret1")
	sig2 := signCookie("session", "secret2")
	if sig1 == sig2 {
		t.Fatal("different secrets must produce different signatures")
	}
}

func TestSignCookie_DifferentIDsDifferentSigs(t *testing.T) {
	sig1 := signCookie("sessionA", "secret")
	sig2 := signCookie("sessionB", "secret")
	if sig1 == sig2 {
		t.Fatal("different session IDs must produce different signatures")
	}
}

// ─── generateSessionID ───────────────────────────────────────────────────────

func TestGenerateSessionID_Length(t *testing.T) {
	id, err := generateSessionID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 24 bytes → base64url (no padding) = ceil(24*4/3) = 32 chars
	if len(id) != 32 {
		t.Fatalf("expected 32 chars, got %d: %q", len(id), id)
	}
}

func TestGenerateSessionID_URLSafe(t *testing.T) {
	for i := 0; i < 20; i++ {
		id, err := generateSessionID()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.ContainsAny(id, "+/=") {
			t.Fatalf("session ID contains non-URL-safe characters: %q", id)
		}
	}
}

func TestGenerateSessionID_Unique(t *testing.T) {
	seen := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		id, err := generateSessionID()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate session ID generated: %q", id)
		}
		seen[id] = true
	}
}

// ─── generateObjectID ────────────────────────────────────────────────────────

func TestGenerateObjectID_Length(t *testing.T) {
	id, err := generateObjectID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 12 bytes → 24 hex chars
	if len(id) != 24 {
		t.Fatalf("expected 24 hex chars, got %d: %q", len(id), id)
	}
}

func TestGenerateObjectID_HexOnly(t *testing.T) {
	id, err := generateObjectID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("non-hex character %q in object ID %q", c, id)
		}
	}
}

func TestGenerateObjectID_Unique(t *testing.T) {
	seen := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		id, err := generateObjectID()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate object ID generated: %q", id)
		}
		seen[id] = true
	}
}

// ─── buildSessionData ────────────────────────────────────────────────────────

func TestBuildSessionData_ValidJSON(t *testing.T) {
	raw, err := buildSessionData("user001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed ghostSessionData
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %s", err, raw)
	}

	if parsed.UserID != "user001" {
		t.Fatalf("user_id: got %q, want user001", parsed.UserID)
	}
	if parsed.Cookie.Path != "/ghost" {
		t.Fatalf("cookie.path: got %q, want /ghost", parsed.Cookie.Path)
	}
	if !parsed.Cookie.HTTPOnly {
		t.Fatal("cookie.httpOnly should be true")
	}
	if !parsed.Cookie.Secure {
		t.Fatal("cookie.secure should be true")
	}
	if parsed.Cookie.SameSite != "lax" {
		t.Fatalf("cookie.sameSite: got %q, want lax", parsed.Cookie.SameSite)
	}
	if parsed.Cookie.OriginalMaxAge != nil {
		t.Fatal("cookie.originalMaxAge should be null")
	}
	if parsed.Cookie.Expires != nil {
		t.Fatal("cookie.expires should be null")
	}
}

func TestBuildSessionData_UserIDPreserved(t *testing.T) {
	userIDs := []string{
		"507f1f77bcf86cd799439011", // typical Ghost ObjectId
		"abc",
		"",
	}
	for _, uid := range userIDs {
		raw, err := buildSessionData(uid)
		if err != nil {
			t.Fatalf("buildSessionData(%q): unexpected error: %v", uid, err)
		}
		var parsed ghostSessionData
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatalf("buildSessionData(%q): invalid JSON: %v", uid, err)
		}
		if parsed.UserID != uid {
			t.Fatalf("user_id mismatch for %q: got %q", uid, parsed.UserID)
		}
	}
}
