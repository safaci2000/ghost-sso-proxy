package oidctoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// makeJWT builds a minimal unsigned JWT with the given claims payload.
func makeJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload, _ := json.Marshal(claims)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + encodedPayload + ".fakesig"
}

// makeCookieHeader builds a Cookie header string containing an IdToken-* cookie.
func makeCookieHeader(tokenValue string) string {
	return "session=abc; IdToken-deadbeef=" + tokenValue + "; other=val"
}

func TestDecoder_HappyPath(t *testing.T) {
	token := makeJWT(map[string]any{
		"email": "alice@example.com",
		"sub":   "sub-001",
	})
	d := NewDecoder()
	identity, err := d.Decode(context.Background(), makeCookieHeader(token))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Email != "alice@example.com" {
		t.Fatalf("email: got %q, want alice@example.com", identity.Email)
	}
	if identity.Sub != "sub-001" {
		t.Fatalf("sub: got %q, want sub-001", identity.Sub)
	}
}

func TestDecoder_EmptyCookieHeader(t *testing.T) {
	d := NewDecoder()
	_, err := d.Decode(context.Background(), "")
	if !errors.Is(err, domain.ErrNoToken) {
		t.Fatalf("expected ErrNoToken, got %v", err)
	}
}

func TestDecoder_NoIdTokenCookie(t *testing.T) {
	d := NewDecoder()
	_, err := d.Decode(context.Background(), "session=abc; other=xyz")
	if !errors.Is(err, domain.ErrNoToken) {
		t.Fatalf("expected ErrNoToken, got %v", err)
	}
}

func TestDecoder_MalformedJWT_TwoSegments(t *testing.T) {
	d := NewDecoder()
	_, err := d.Decode(context.Background(), makeCookieHeader("header.payload"))
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestDecoder_MalformedJWT_BadBase64(t *testing.T) {
	d := NewDecoder()
	_, err := d.Decode(context.Background(), makeCookieHeader("hdr.!!!.sig"))
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestDecoder_MissingEmailClaim(t *testing.T) {
	token := makeJWT(map[string]any{"sub": "sub-001"}) // no email
	d := NewDecoder()
	_, err := d.Decode(context.Background(), makeCookieHeader(token))
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for missing email, got %v", err)
	}
}

func TestDecoder_SubIsOptional(t *testing.T) {
	token := makeJWT(map[string]any{"email": "bob@example.com"}) // no sub
	d := NewDecoder()
	identity, err := d.Decode(context.Background(), makeCookieHeader(token))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Sub != "" {
		t.Fatalf("expected empty sub, got %q", identity.Sub)
	}
}

// TestDecoder_MultipleCookies verifies the first IdToken-* cookie wins.
func TestDecoder_MultipleCookies(t *testing.T) {
	firstToken := makeJWT(map[string]any{"email": "first@example.com", "sub": "1"})
	secondToken := makeJWT(map[string]any{"email": "second@example.com", "sub": "2"})
	cookieHeader := "IdToken-aaa=" + firstToken + "; IdToken-bbb=" + secondToken

	d := NewDecoder()
	identity, err := d.Decode(context.Background(), cookieHeader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Email != "first@example.com" {
		t.Fatalf("expected first@example.com, got %q", identity.Email)
	}
}

// ─── Unit tests for unexported helpers ───────────────────────────────────────

func TestFindIDToken_ByPrefix(t *testing.T) {
	token := makeJWT(map[string]any{"email": "x@x.com"})
	val, err := findIDToken("foo=bar; IdToken-12345=" + token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != token {
		t.Fatalf("got %q, want %q", val, token)
	}
}

func TestFindIDToken_Missing(t *testing.T) {
	_, err := findIDToken("session=abc")
	if !errors.Is(err, domain.ErrNoToken) {
		t.Fatalf("expected ErrNoToken, got %v", err)
	}
}

func TestDecodeJWTPayload_Valid(t *testing.T) {
	token := makeJWT(map[string]any{"email": "test@test.com", "sub": "s1"})
	identity, err := decodeJWTPayload(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Email != "test@test.com" {
		t.Fatalf("email mismatch: %q", identity.Email)
	}
}

func TestDecodeJWTPayload_NotThreeSegments(t *testing.T) {
	for _, tok := range []string{"", "one", "one.two", "a.b.c.d"} {
		if strings.Count(tok, ".") == 2 {
			continue // skip valid 3-segment tokens
		}
		_, err := decodeJWTPayload(tok)
		if !errors.Is(err, domain.ErrInvalidToken) {
			t.Fatalf("token %q: expected ErrInvalidToken, got %v", tok, err)
		}
	}
}
