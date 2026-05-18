package oidctoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// makeUserInfoServer starts a test HTTP server that returns a fixed userinfo JSON payload.
// The caller must call srv.Close() when done.
func makeUserInfoServer(t *testing.T, statusCode int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("userinfo request missing Bearer authorization; got %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		fmt.Fprint(w, body)
	}))
}

// ─── Bearer token + userinfo endpoint (production path) ──────────────────────

func TestDecoder_UserInfo_HappyPath(t *testing.T) {
	srv := makeUserInfoServer(t, http.StatusOK, `{"email":"alice@example.com","sub":"sub-001"}`)
	defer srv.Close()

	d := NewDecoder(srv.URL)
	identity, err := d.Decode(context.Background(), "", "Bearer sometoken")
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

func TestDecoder_UserInfo_SubOptional(t *testing.T) {
	srv := makeUserInfoServer(t, http.StatusOK, `{"email":"bob@example.com"}`)
	defer srv.Close()

	d := NewDecoder(srv.URL)
	identity, err := d.Decode(context.Background(), "", "Bearer sometoken")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Email != "bob@example.com" {
		t.Fatalf("email: got %q, want bob@example.com", identity.Email)
	}
	if identity.Sub != "" {
		t.Fatalf("sub: got %q, want empty", identity.Sub)
	}
}

func TestDecoder_UserInfo_MissingEmail(t *testing.T) {
	srv := makeUserInfoServer(t, http.StatusOK, `{"sub":"sub-only"}`)
	defer srv.Close()

	d := NewDecoder(srv.URL)
	_, err := d.Decode(context.Background(), "", "Bearer sometoken")
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestDecoder_UserInfo_HTTPError(t *testing.T) {
	srv := makeUserInfoServer(t, http.StatusUnauthorized, `{"error":"invalid_token"}`)
	defer srv.Close()

	d := NewDecoder(srv.URL)
	_, err := d.Decode(context.Background(), "", "Bearer badtoken")
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestDecoder_UserInfo_InvalidJSON(t *testing.T) {
	srv := makeUserInfoServer(t, http.StatusOK, `not-json`)
	defer srv.Close()

	d := NewDecoder(srv.URL)
	_, err := d.Decode(context.Background(), "", "Bearer sometoken")
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestDecoder_UserInfo_WinsOverCookie(t *testing.T) {
	// When userinfo URL is set, Bearer token path wins even if a cookie is present.
	srv := makeUserInfoServer(t, http.StatusOK, `{"email":"userinfo@example.com","sub":"u1"}`)
	defer srv.Close()

	cookieJWT := makeJWT(map[string]any{"email": "cookie@example.com", "sub": "c1"})
	d := NewDecoder(srv.URL)
	identity, err := d.Decode(context.Background(), makeCookieHeader(cookieJWT), "Bearer sometoken")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Email != "userinfo@example.com" {
		t.Fatalf("expected userinfo@example.com, got %q", identity.Email)
	}
}

// ─── Bearer token (local dev — no userinfo URL, falls back to JWT decode) ────

func TestDecoder_BearerToken_HappyPath(t *testing.T) {
	jwt := makeJWT(map[string]any{"email": "alice@example.com", "sub": "sub-001"})
	d := NewDecoder("") // no userinfo URL → local JWT decode
	identity, err := d.Decode(context.Background(), "", "Bearer "+jwt)
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

func TestDecoder_BearerToken_WinsOverCookie(t *testing.T) {
	// Bearer JWT should be used even when a valid IdToken-* cookie is also present.
	bearerJWT := makeJWT(map[string]any{"email": "bearer@example.com", "sub": "b1"})
	cookieJWT := makeJWT(map[string]any{"email": "cookie@example.com", "sub": "c1"})
	d := NewDecoder("") // local JWT decode
	identity, err := d.Decode(context.Background(), makeCookieHeader(cookieJWT), "Bearer "+bearerJWT)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Email != "bearer@example.com" {
		t.Fatalf("expected bearer@example.com, got %q", identity.Email)
	}
}

func TestDecoder_BearerToken_OpaqueTokenReturnsError(t *testing.T) {
	// Opaque / non-JWT bearer value must return ErrInvalidToken immediately
	// when no userinfo URL is configured.
	d := NewDecoder("") // local JWT decode only
	_, err := d.Decode(context.Background(), makeCookieHeader("ignored"), "Bearer notajwt")
	if err == nil {
		t.Fatal("expected error for opaque bearer token, got nil")
	}
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestDecoder_BearerToken_MissingEmailReturnsError(t *testing.T) {
	// Bearer JWT present but missing email claim → ErrInvalidToken.
	bearerNoEmail := makeJWT(map[string]any{"sub": "no-email"})
	d := NewDecoder("") // local JWT decode
	_, err := d.Decode(context.Background(), makeCookieHeader("ignored"), "Bearer "+bearerNoEmail)
	if err == nil {
		t.Fatal("expected error for bearer JWT missing email, got nil")
	}
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

// ─── Cookie fallback path ─────────────────────────────────────────────────────

func TestDecoder_HappyPath(t *testing.T) {
	token := makeJWT(map[string]any{
		"email": "alice@example.com",
		"sub":   "sub-001",
	})
	d := NewDecoder("")
	identity, err := d.Decode(context.Background(), makeCookieHeader(token), "")
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
	d := NewDecoder("")
	_, err := d.Decode(context.Background(), "", "")
	if !errors.Is(err, domain.ErrNoToken) {
		t.Fatalf("expected ErrNoToken, got %v", err)
	}
}

func TestDecoder_NoIdTokenCookie(t *testing.T) {
	d := NewDecoder("")
	_, err := d.Decode(context.Background(), "session=abc; other=xyz", "")
	if !errors.Is(err, domain.ErrNoToken) {
		t.Fatalf("expected ErrNoToken, got %v", err)
	}
}

func TestDecoder_MalformedJWT_TwoSegments(t *testing.T) {
	d := NewDecoder("")
	_, err := d.Decode(context.Background(), makeCookieHeader("header.payload"), "")
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestDecoder_MalformedJWT_BadBase64(t *testing.T) {
	d := NewDecoder("")
	_, err := d.Decode(context.Background(), makeCookieHeader("hdr.!!!.sig"), "")
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestDecoder_MissingEmailClaim(t *testing.T) {
	token := makeJWT(map[string]any{"sub": "sub-001"}) // no email
	d := NewDecoder("")
	_, err := d.Decode(context.Background(), makeCookieHeader(token), "")
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for missing email, got %v", err)
	}
}

func TestDecoder_SubIsOptional(t *testing.T) {
	token := makeJWT(map[string]any{"email": "bob@example.com"}) // no sub
	d := NewDecoder("")
	identity, err := d.Decode(context.Background(), makeCookieHeader(token), "")
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

	d := NewDecoder("")
	identity, err := d.Decode(context.Background(), cookieHeader, "")
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
