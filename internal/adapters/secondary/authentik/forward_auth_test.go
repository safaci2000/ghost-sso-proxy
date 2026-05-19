package authentik

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// makeServer returns an httptest.Server whose handler is set by the caller.
func makeServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// ─── Check: authenticated (200 + X-Authentik-Email) ──────────────────────────

func TestCheck_Authenticated_ReturnsEmail(t *testing.T) {
	srv := makeServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Authentik-Email", "user@example.com")
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	email, redirect, cookies, err := c.Check(context.Background(), "", "blog.example.com", "https", "/ghost/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "user@example.com" {
		t.Fatalf("email: got %q, want %q", email, "user@example.com")
	}
	if redirect != "" {
		t.Fatalf("expected empty redirectURL, got %q", redirect)
	}
	if len(cookies) != 0 {
		t.Fatalf("expected no cookies on 200, got %v", cookies)
	}
}

func TestCheck_Authenticated_EmptyEmail_ReturnsError(t *testing.T) {
	srv := makeServer(func(w http.ResponseWriter, r *http.Request) {
		// 200 but no X-Authentik-Email header
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	_, _, _, err := c.Check(context.Background(), "", "blog.example.com", "https", "/ghost/")
	if err == nil {
		t.Fatal("expected error when X-Authentik-Email is missing, got nil")
	}
}

// ─── Check: unauthenticated (302 + Location) ──────────────────────────────────

func TestCheck_Redirect_ReturnsLocation(t *testing.T) {
	loginURL := "https://auth.example.com/if/flow/ghost-login/"
	srv := makeServer(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, loginURL, http.StatusFound)
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	email, redirect, _, err := c.Check(context.Background(), "", "blog.example.com", "https", "/ghost/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if redirect != loginURL {
		t.Fatalf("redirectURL: got %q, want %q", redirect, loginURL)
	}
	if email != "" {
		t.Fatalf("expected empty email, got %q", email)
	}
}

func TestCheck_Redirect_MissingLocation_ReturnsError(t *testing.T) {
	srv := makeServer(func(w http.ResponseWriter, r *http.Request) {
		// 302 but no Location header
		w.WriteHeader(http.StatusFound)
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	_, _, _, err := c.Check(context.Background(), "", "blog.example.com", "https", "/ghost/")
	if err == nil {
		t.Fatal("expected error when Location is missing from 302, got nil")
	}
}

func TestCheck_Redirect_ForwardsSetCookies(t *testing.T) {
	loginURL := "https://auth.example.com/application/o/authorize/?state=xyz"
	cookie1 := "authentik_proxy_abc=state_token_1; Path=/; HttpOnly; Secure; SameSite=Lax"
	cookie2 := "authentik_proxy_def=state_token_2; Path=/; HttpOnly; Secure; SameSite=Lax"
	srv := makeServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", cookie1)
		w.Header().Add("Set-Cookie", cookie2)
		w.Header().Set("Location", loginURL)
		w.WriteHeader(http.StatusFound)
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	email, redirect, cookies, err := c.Check(context.Background(), "", "blog.example.com", "https", "/ghost/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "" {
		t.Fatalf("expected empty email on redirect, got %q", email)
	}
	if redirect != loginURL {
		t.Fatalf("redirectURL: got %q, want %q", redirect, loginURL)
	}
	if len(cookies) != 2 {
		t.Fatalf("expected 2 Set-Cookie values, got %d: %v", len(cookies), cookies)
	}
	if cookies[0] != cookie1 {
		t.Errorf("cookies[0]: got %q, want %q", cookies[0], cookie1)
	}
	if cookies[1] != cookie2 {
		t.Errorf("cookies[1]: got %q, want %q", cookies[1], cookie2)
	}
}

func TestCheck_Redirect_NoCookies_ReturnsEmptySlice(t *testing.T) {
	loginURL := "https://auth.example.com/if/flow/ghost-login/"
	srv := makeServer(func(w http.ResponseWriter, r *http.Request) {
		// 302 with no Set-Cookie headers
		w.Header().Set("Location", loginURL)
		w.WriteHeader(http.StatusFound)
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	_, _, cookies, err := c.Check(context.Background(), "", "blog.example.com", "https", "/ghost/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// nil and empty slice are both acceptable — just must not panic
	if len(cookies) != 0 {
		t.Fatalf("expected no cookies when none are set, got %v", cookies)
	}
}

// ─── Check: server error ──────────────────────────────────────────────────────

func TestCheck_ServerError_ReturnsError(t *testing.T) {
	srv := makeServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	_, _, _, err := c.Check(context.Background(), "", "blog.example.com", "https", "/ghost/")
	if err == nil {
		t.Fatal("expected error for non-200/302 status, got nil")
	}
}

func TestCheck_EmptyEndpointURL_ReturnsError(t *testing.T) {
	c := NewClient("")
	_, _, _, err := c.Check(context.Background(), "", "blog.example.com", "https", "/ghost/")
	if err == nil {
		t.Fatal("expected error when endpointURL is empty, got nil")
	}
}

// ─── Check: header forwarding ─────────────────────────────────────────────────

func TestCheck_ForwardsRequestHeaders(t *testing.T) {
	var (
		gotCookie  string
		gotHost    string
		gotProto   string
		gotURI     string
	)
	srv := makeServer(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		gotHost = r.Header.Get("X-Forwarded-Host")
		gotProto = r.Header.Get("X-Forwarded-Proto")
		gotURI = r.Header.Get("X-Forwarded-Uri")
		w.Header().Set("X-Authentik-Email", "user@example.com")
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	cookie := "authentik_session=abc123; other=val"
	_, _, _, err := c.Check(context.Background(), cookie, "blog.example.com", "https", "/ghost/editor/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(gotCookie, "authentik_session=abc123") {
		t.Errorf("Cookie not forwarded correctly: got %q", gotCookie)
	}
	if gotHost != "blog.example.com" {
		t.Errorf("X-Forwarded-Host: got %q, want %q", gotHost, "blog.example.com")
	}
	if gotProto != "https" {
		t.Errorf("X-Forwarded-Proto: got %q, want %q", gotProto, "https")
	}
	if gotURI != "/ghost/editor/" {
		t.Errorf("X-Forwarded-Uri: got %q, want %q", gotURI, "/ghost/editor/")
	}
}

func TestCheck_NoCookieHeader_DoesNotSendCookie(t *testing.T) {
	var gotCookie string
	srv := makeServer(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.Header().Set("X-Authentik-Email", "user@example.com")
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	_, _, _, err := c.Check(context.Background(), "", "blog.example.com", "https", "/ghost/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotCookie != "" {
		t.Errorf("expected no Cookie header when cookieHeader is empty, got %q", gotCookie)
	}
}
