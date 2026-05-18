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

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

// stubAuth is a minimal AuthService stub for unit tests.
type stubAuth struct {
	cookie string
	err    error
}

func (s *stubAuth) EnsureSession(_ context.Context, _, _ string) (string, error) {
	return s.cookie, s.err
}

// testServer returns a *Server wired with the given stub, using the
// package-level cookieMaxAge default (180 days) so tests remain self-contained.
func testServer(stub *stubAuth) *Server {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return &Server{
		auth:              stub,
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

// ─── Check: fast path ─────────────────────────────────────────────────────────

func TestCheck_FastPath_ReturnsOkResponse(t *testing.T) {
	// When EnsureSession returns ("", nil) the session cookie is already present.
	srv := testServer(&stubAuth{cookie: "", err: nil})
	resp, err := srv.Check(context.Background(), checkReq(map[string]string{
		"cookie": "ghost-admin-api-session=s:id.sig",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatalf("expected OkResponse, got %T", resp.HttpResponse)
	}
}

func TestCheck_FastPath_StatusCodeOK(t *testing.T) {
	srv := testServer(&stubAuth{cookie: "", err: nil})
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	if resp.Status.GetCode() != int32(codes.OK) {
		t.Fatalf("expected gRPC code OK, got %d", resp.Status.GetCode())
	}
}

func TestCheck_FastPath_StripsAuthorizationHeader(t *testing.T) {
	srv := testServer(&stubAuth{cookie: "", err: nil})
	resp, _ := srv.Check(context.Background(), checkReq(map[string]string{
		"authorization": "Bearer jwt.token.here",
	}))
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("expected OkResponse")
	}
	found := false
	for _, h := range ok.HeadersToRemove {
		if h == "authorization" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'authorization' in HeadersToRemove, got %v", ok.HeadersToRemove)
	}
}

// ─── Check: slow path ─────────────────────────────────────────────────────────

func TestCheck_SlowPath_ReturnsDeniedResponse(t *testing.T) {
	// When EnsureSession returns a signed cookie the server must issue a redirect.
	srv := testServer(&stubAuth{cookie: "s:id.hmacSig", err: nil})
	resp, err := srv.Check(context.Background(), checkReq(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("expected DeniedResponse, got %T", resp.HttpResponse)
	}
}

func TestCheck_SlowPath_Status302(t *testing.T) {
	srv := testServer(&stubAuth{cookie: "s:id.sig", err: nil})
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
	srv := testServer(&stubAuth{cookie: "s:id.sig", err: nil})
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
	srv := testServer(&stubAuth{cookie: "s:id.sig", err: nil})
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
	srv := testServer(&stubAuth{cookie: "s:id.sig", err: nil})
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse")
	}
	if len(denied.Headers) != 2 {
		t.Fatalf("expected 2 headers (location + set-cookie), got %d", len(denied.Headers))
	}
}

// ─── Check: error path ────────────────────────────────────────────────────────

func TestCheck_ErrorPath_FailOpen(t *testing.T) {
	// Any error from EnsureSession must produce an OkResponse (fail-open policy).
	srv := testServer(&stubAuth{err: errors.New("some error")})
	resp, err := srv.Check(context.Background(), checkReq(nil))
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatalf("expected OkResponse on error, got %T", resp.HttpResponse)
	}
}

func TestCheck_ErrorPath_ErrNoToken_FailOpen(t *testing.T) {
	// ErrNoToken (expected during OIDC callback) must also fail open.
	srv := testServer(&stubAuth{err: domain.ErrNoToken})
	resp, err := srv.Check(context.Background(), checkReq(nil))
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetOkResponse() == nil {
		t.Fatalf("expected OkResponse for ErrNoToken, got %T", resp.HttpResponse)
	}
}

func TestCheck_ErrorPath_StripsAuthorizationHeader(t *testing.T) {
	srv := testServer(&stubAuth{err: errors.New("some error")})
	resp, _ := srv.Check(context.Background(), checkReq(nil))
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("expected OkResponse")
	}
	found := false
	for _, h := range ok.HeadersToRemove {
		if h == "authorization" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'authorization' in HeadersToRemove on error path, got %v", ok.HeadersToRemove)
	}
}

// ─── buildSetCookieHeader ─────────────────────────────────────────────────────

func TestBuildSetCookieHeader_Format(t *testing.T) {
	srv := testServer(&stubAuth{})
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
	srv := testServer(&stubAuth{})
	got := srv.buildSetCookieHeader("s:id.sig")

	required := []string{"HttpOnly", "Secure", "SameSite=None", "Path=/ghost", "Max-Age="}
	for _, attr := range required {
		if !strings.Contains(got, attr) {
			t.Errorf("Set-Cookie header missing %q: %q", attr, got)
		}
	}
}

func TestBuildSetCookieHeader_MaxAge(t *testing.T) {
	const wantMaxAge = 180 * 24 * 60 * 60 // 15552000 — must match defaultSessionMaxAgeDays in session_store.go
	if cookieMaxAge != wantMaxAge {
		t.Fatalf("expected cookieMaxAge=%d (180 days), got %d", wantMaxAge, cookieMaxAge)
	}
	srv := testServer(&stubAuth{})
	got := srv.buildSetCookieHeader("s:id.sig")
	wantAttr := fmt.Sprintf("Max-Age=%d", wantMaxAge)
	if !strings.Contains(got, wantAttr) {
		t.Fatalf("expected %q in %q", wantAttr, got)
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
	srv := testServer(&stubAuth{})
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
	resp := okResponse(nil)
	if resp.Status.GetCode() != int32(codes.OK) {
		t.Fatalf("expected gRPC code OK, got %d", resp.Status.GetCode())
	}
}

func TestOkResponse_HeadersToRemove(t *testing.T) {
	resp := okResponse([]string{"authorization", "x-custom"})
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("expected OkResponse")
	}
	if len(ok.HeadersToRemove) != 2 {
		t.Fatalf("expected 2 HeadersToRemove, got %v", ok.HeadersToRemove)
	}
}

func TestOkResponse_NilHeadersToRemove(t *testing.T) {
	resp := okResponse(nil)
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("expected OkResponse")
	}
	if len(ok.HeadersToRemove) != 0 {
		t.Fatalf("expected empty HeadersToRemove, got %v", ok.HeadersToRemove)
	}
}
