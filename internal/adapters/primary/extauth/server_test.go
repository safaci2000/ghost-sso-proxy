package extauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
)

// ─── Test stubs ───────────────────────────────────────────────────────────────

// stubAuth is a minimal AuthService stub for unit tests.
type stubAuth struct {
	cookie string
	err    error
}

func (s *stubAuth) EnsureSession(_ context.Context, _, _ string) (string, error) {
	return s.cookie, s.err
}

// stubAuthentik is a minimal forwardAuth stub for unit tests.
type stubAuthentik struct {
	email       string
	redirectURL string
	setCookies  []string
	err         error
}

func (s *stubAuthentik) Check(_ context.Context, _, _, _, _ string) (string, string, []string, error) {
	return s.email, s.redirectURL, s.setCookies, s.err
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// testServer returns a *Server wired with the given stubs, using the
// package-level cookieMaxAge default so tests remain self-contained.
func testServer(auth *stubAuth, ak *stubAuthentik) *Server {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return &Server{
		auth:              auth,
		authentik:         ak,
		logger:            logger,
		sessionMaxAgeSecs: cookieMaxAge,
	}
}

// checkReq builds a minimal CheckRequest with the given headers map.
func checkReq(headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Headers: headers,
				},
			},
		},
	}
}

// authenticated returns a stubAuthentik that reports the user as logged in.
func authenticated(email string) *stubAuthentik {
	return &stubAuthentik{email: email}
}

// ─── Check: Authentik redirect (not logged in) ────────────────────────────────

func TestCheck_AuthentikRedirect_ReturnsDeniedResponse(t *testing.T) {
	loginURL := "https://auth.example.com/if/flow/ghost-login/"
	srv := testServer(
		&stubAuth{},
		&stubAuthentik{redirectURL: loginURL},
	)
	resp, err := srv.Check(context.Background(), checkReq(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetDeniedResponse() == nil {
		t.Fatalf("expected DeniedResponse, got %T", resp.HttpResponse)
	}
}

func TestCheck_AuthentikRedirect_Status302(t *testing.T) {
	loginURL := "https://auth.example.com/if/flow/ghost-login/"
	srv := testServer(&stubAuth{}, &stubAuthentik{redirectURL: loginURL})
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	if denied.Status == nil || denied.Status.Code != typev3.StatusCode_Found {
		t.Fatalf("expected HTTP 302 Found, got %v", denied.Status)
	}
}

func TestCheck_AuthentikRedirect_LocationIsAuthentikURL(t *testing.T) {
	loginURL := "https://auth.example.com/if/flow/ghost-login/"
	srv := testServer(&stubAuth{}, &stubAuthentik{redirectURL: loginURL})
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	var location string
	for _, h := range denied.Headers {
		if strings.EqualFold(h.Header.Key, "location") {
			location = h.Header.Value
		}
	}
	if location != loginURL {
		t.Fatalf("location: got %q, want %q", location, loginURL)
	}
}

func TestCheck_AuthentikRedirect_NoSetCookieHeader_WhenAuthentikSendsNone(t *testing.T) {
	// When Authentik sends no Set-Cookie headers, none should appear in the DeniedResponse.
	srv := testServer(&stubAuth{}, &stubAuthentik{redirectURL: "https://auth.example.com/login"})
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	for _, h := range denied.Headers {
		if strings.EqualFold(h.Header.Key, "set-cookie") {
			t.Fatalf("expected no set-cookie when Authentik sends none, got: %q", h.Header.Value)
		}
	}
}

func TestCheck_AuthentikRedirect_ForwardsAuthentikCookies(t *testing.T) {
	// When Authentik returns Set-Cookie (PKCE state), they must appear in the DeniedResponse
	// so the browser can complete the OAuth2 callback.
	proxyCookie := "authentik_proxy_abc=state; Path=/; HttpOnly; Secure; SameSite=Lax"
	srv := testServer(&stubAuth{}, &stubAuthentik{
		redirectURL: "https://auth.example.com/application/o/authorize/?state=xyz",
		setCookies:  []string{proxyCookie},
	})
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	var found []string
	for _, h := range denied.Headers {
		if strings.EqualFold(h.Header.Key, "set-cookie") {
			found = append(found, h.Header.Value)
		}
	}
	if len(found) != 1 || found[0] != proxyCookie {
		t.Fatalf("set-cookie headers: got %v, want [%q]", found, proxyCookie)
	}
}

// ─── Check: Authentik error → fail-open ──────────────────────────────────────

func TestCheck_AuthentikError_FailOpen(t *testing.T) {
	srv := testServer(
		&stubAuth{},
		&stubAuthentik{err: errors.New("connection refused")},
	)
	resp, err := srv.Check(context.Background(), checkReq(nil))
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetOkResponse() == nil {
		t.Fatalf("expected OkResponse on Authentik error, got %T", resp.HttpResponse)
	}
}

func TestCheck_AuthentikError_StatusCodeOK(t *testing.T) {
	srv := testServer(&stubAuth{}, &stubAuthentik{err: errors.New("timeout")})
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	if resp.Status.GetCode() != int32(codes.OK) {
		t.Fatalf("expected gRPC code OK on fail-open, got %d", resp.Status.GetCode())
	}
}

// ─── Check: fast path (ghost session already present) ─────────────────────────

func TestCheck_FastPath_ReturnsOkResponse(t *testing.T) {
	// EnsureSession returns ("", nil) when the ghost session cookie is present.
	srv := testServer(
		&stubAuth{cookie: "", err: nil},
		authenticated("user@example.com"),
	)
	resp, err := srv.Check(context.Background(), checkReq(map[string]string{
		"cookie": "ghost-admin-api-session=s:id.sig",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetOkResponse() == nil {
		t.Fatalf("expected OkResponse, got %T", resp.HttpResponse)
	}
}

func TestCheck_FastPath_StatusCodeOK(t *testing.T) {
	srv := testServer(&stubAuth{cookie: "", err: nil}, authenticated("user@example.com"))
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	if resp.Status.GetCode() != int32(codes.OK) {
		t.Fatalf("expected gRPC code OK, got %d", resp.Status.GetCode())
	}
}

// ─── Check: slow path (ghost session created) ─────────────────────────────────

func TestCheck_SlowPath_ReturnsDeniedResponse(t *testing.T) {
	srv := testServer(
		&stubAuth{cookie: "s:id.hmacSig", err: nil},
		authenticated("user@example.com"),
	)
	resp, err := srv.Check(context.Background(), checkReq(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetDeniedResponse() == nil {
		t.Fatalf("expected DeniedResponse, got %T", resp.HttpResponse)
	}
}

func TestCheck_SlowPath_Status302(t *testing.T) {
	srv := testServer(&stubAuth{cookie: "s:id.sig", err: nil}, authenticated("user@example.com"))
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	if denied.Status == nil || denied.Status.Code != typev3.StatusCode_Found {
		t.Fatalf("expected HTTP 302 Found, got %v", denied.Status)
	}
}

func TestCheck_SlowPath_LocationHeader(t *testing.T) {
	srv := testServer(&stubAuth{cookie: "s:id.sig", err: nil}, authenticated("user@example.com"))
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	var location string
	for _, h := range denied.Headers {
		if strings.EqualFold(h.Header.Key, "location") {
			location = h.Header.Value
		}
	}
	if location != ghostAdminPath {
		t.Fatalf("location: got %q, want %q", location, ghostAdminPath)
	}
}

func TestCheck_SlowPath_SetCookieHeader(t *testing.T) {
	srv := testServer(&stubAuth{cookie: "s:id.sig", err: nil}, authenticated("user@example.com"))
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	var setCookie string
	for _, h := range denied.Headers {
		if strings.EqualFold(h.Header.Key, "set-cookie") {
			setCookie = h.Header.Value
		}
	}
	wantPrefix := ghostSessionCookieName + "=s:id.sig"
	if !strings.HasPrefix(setCookie, wantPrefix) {
		t.Fatalf("set-cookie: got %q, want prefix %q", setCookie, wantPrefix)
	}
}

func TestCheck_SlowPath_TwoResponseHeaders(t *testing.T) {
	// DeniedResponse must carry exactly location + set-cookie.
	srv := testServer(&stubAuth{cookie: "s:id.sig", err: nil}, authenticated("user@example.com"))
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	if len(denied.Headers) != 2 {
		t.Fatalf("expected 2 headers (location + set-cookie), got %d", len(denied.Headers))
	}
}

// ─── Check: auth service error → fail-open ────────────────────────────────────

func TestCheck_AuthServiceError_FailOpen(t *testing.T) {
	srv := testServer(
		&stubAuth{err: errors.New("db down")},
		authenticated("user@example.com"),
	)
	resp, err := srv.Check(context.Background(), checkReq(nil))
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetOkResponse() == nil {
		t.Fatalf("expected OkResponse on auth error, got %T", resp.HttpResponse)
	}
}

// ─── buildSetCookieHeader ─────────────────────────────────────────────────────

func TestBuildSetCookieHeader_Format(t *testing.T) {
	srv := testServer(&stubAuth{}, authenticated(""))
	signed := "s:myID.hmacSig"
	got := srv.buildSetCookieHeader(signed)

	want := fmt.Sprintf(
		"ghost-admin-api-session=%s; Path=/ghost; HttpOnly; Secure; SameSite=None; Max-Age=%d",
		signed, cookieMaxAge,
	)
	if got != want {
		t.Fatalf("Set-Cookie header mismatch:\n  got  %q\n  want %q", got, want)
	}
}

func TestBuildSetCookieHeader_ContainsRequiredAttributes(t *testing.T) {
	srv := testServer(&stubAuth{}, authenticated(""))
	got := srv.buildSetCookieHeader("s:id.sig")

	required := []string{"HttpOnly", "Secure", "SameSite=None", "Path=/ghost", "Max-Age="}
	for _, attr := range required {
		if !strings.Contains(got, attr) {
			t.Errorf("Set-Cookie header missing %q: %q", attr, got)
		}
	}
}

func TestBuildSetCookieHeader_MaxAge(t *testing.T) {
	const wantMaxAge = 180 * 24 * 60 * 60 // 15552000 — must match defaultSessionMaxAgeDays
	if cookieMaxAge != wantMaxAge {
		t.Fatalf("expected cookieMaxAge=%d (180 days), got %d", wantMaxAge, cookieMaxAge)
	}
	srv := testServer(&stubAuth{}, authenticated(""))
	got := srv.buildSetCookieHeader("s:id.sig")
	wantAttr := fmt.Sprintf("Max-Age=%d", wantMaxAge)
	if !strings.Contains(got, wantAttr) {
		t.Fatalf("expected %q in %q", wantAttr, got)
	}
}

// ─── deniedRedirectTo ─────────────────────────────────────────────────────────

func TestDeniedRedirectTo_Status302(t *testing.T) {
	resp := deniedRedirectTo("https://auth.example.com/login", nil)
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	if denied.Status == nil || denied.Status.Code != typev3.StatusCode_Found {
		t.Fatalf("expected 302 Found, got %v", denied.Status)
	}
}

func TestDeniedRedirectTo_LocationHeader(t *testing.T) {
	loginURL := "https://auth.example.com/if/flow/ghost-login/"
	resp := deniedRedirectTo(loginURL, nil)
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	var location string
	for _, h := range denied.Headers {
		if strings.EqualFold(h.Header.Key, "location") {
			location = h.Header.Value
		}
	}
	if location != loginURL {
		t.Fatalf("location: got %q, want %q", location, loginURL)
	}
}

func TestDeniedRedirectTo_NoCookies_ExactlyOneHeader(t *testing.T) {
	resp := deniedRedirectTo("https://auth.example.com/login", nil)
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	if len(denied.Headers) != 1 {
		t.Fatalf("expected exactly 1 header (location), got %d", len(denied.Headers))
	}
}

func TestDeniedRedirectTo_WithCookies_IncludesCookieHeaders(t *testing.T) {
	c1 := "authentik_proxy_a=tok1; Path=/; HttpOnly; Secure; SameSite=Lax"
	c2 := "authentik_proxy_b=tok2; Path=/; HttpOnly; Secure; SameSite=Lax"
	resp := deniedRedirectTo("https://auth.example.com/login", []string{c1, c2})
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	// 1 location + 2 set-cookie
	if len(denied.Headers) != 3 {
		t.Fatalf("expected 3 headers (location + 2 set-cookie), got %d", len(denied.Headers))
	}
	var setCookies []string
	for _, h := range denied.Headers {
		if strings.EqualFold(h.Header.Key, "set-cookie") {
			setCookies = append(setCookies, h.Header.Value)
		}
	}
	if len(setCookies) != 2 {
		t.Fatalf("expected 2 set-cookie headers, got %d: %v", len(setCookies), setCookies)
	}
}

// ─── deniedRedirectWithCookie ─────────────────────────────────────────────────

func TestDeniedRedirectWithCookie_Status302(t *testing.T) {
	resp := deniedRedirectWithCookie("/ghost/", "ghost-admin-api-session=s:id.sig; Path=/ghost")
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	if denied.Status == nil || denied.Status.Code != typev3.StatusCode_Found {
		t.Fatalf("expected 302 Found, got %v", denied.Status)
	}
}

func TestDeniedRedirectWithCookie_LocationHeader(t *testing.T) {
	resp := deniedRedirectWithCookie(ghostAdminPath, "ghost-admin-api-session=s:id.sig; Path=/ghost")
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	var location string
	for _, h := range denied.Headers {
		if strings.EqualFold(h.Header.Key, "location") {
			location = h.Header.Value
		}
	}
	if location != ghostAdminPath {
		t.Fatalf("location: got %q, want %q", location, ghostAdminPath)
	}
}

func TestDeniedRedirectWithCookie_SetCookieHeader(t *testing.T) {
	srv := testServer(&stubAuth{}, authenticated(""))
	cookieVal := srv.buildSetCookieHeader("s:id.sig")
	resp := deniedRedirectWithCookie(ghostAdminPath, cookieVal)
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	var setCookie string
	for _, h := range denied.Headers {
		if strings.EqualFold(h.Header.Key, "set-cookie") {
			setCookie = h.Header.Value
		}
	}
	if setCookie != cookieVal {
		t.Fatalf("set-cookie: got %q, want %q", setCookie, cookieVal)
	}
}

// ─── okResponse ───────────────────────────────────────────────────────────────

func TestOkResponse_StatusCodeOK(t *testing.T) {
	resp := okResponse()
	if resp.Status.GetCode() != int32(codes.OK) {
		t.Fatalf("expected gRPC code OK, got %d", resp.Status.GetCode())
	}
}

func TestOkResponse_NoHeadersToRemove(t *testing.T) {
	resp := okResponse()
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("expected OkResponse")
	}
	if len(ok.HeadersToRemove) != 0 {
		t.Fatalf("expected no HeadersToRemove, got %v", ok.HeadersToRemove)
	}
}

// ─── firstNonEmpty ────────────────────────────────────────────────────────────

func TestFirstNonEmpty(t *testing.T) {
	cases := []struct {
		vals []string
		want string
	}{
		{[]string{"a", "b"}, "a"},
		{[]string{"", "b"}, "b"},
		{[]string{"", ""}, ""},
		{[]string{}, ""},
		{[]string{"", "b", "c"}, "b"},
	}
	for _, tc := range cases {
		if got := firstNonEmpty(tc.vals...); got != tc.want {
			t.Errorf("firstNonEmpty(%v) = %q, want %q", tc.vals, got, tc.want)
		}
	}
}
