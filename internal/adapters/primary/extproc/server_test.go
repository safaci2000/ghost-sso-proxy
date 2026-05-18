package extproc

import (
	"fmt"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

// testServer returns a minimal *Server suitable for unit-testing methods that
// don't need a real AuthService. It uses the package-level cookieMaxAge default
// (180 days) so tests remain self-contained.
func testServer() *Server {
	return &Server{sessionMaxAgeSecs: cookieMaxAge}
}

// ─── buildSetCookieHeader ─────────────────────────────────────────────────────

func TestBuildSetCookieHeader_Format(t *testing.T) {
	srv := testServer()
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
	srv := testServer()
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
	srv := testServer()
	got := srv.buildSetCookieHeader("s:id.sig")
	wantAttr := fmt.Sprintf("Max-Age=%d", wantMaxAge)
	if !strings.Contains(got, wantAttr) {
		t.Fatalf("expected %q in %q", wantAttr, got)
	}
}

// ─── immediateRedirectWithCookie ──────────────────────────────────────────────

func TestImmediateRedirectWithCookie_Status302(t *testing.T) {
	resp := immediateRedirectWithCookie("/ghost/", "ghost-admin-api-session=s:id.sig; Path=/ghost")

	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse")
	}
	if ir.Status == nil || ir.Status.Code != typev3.StatusCode_Found {
		t.Fatalf("expected 302 Found, got %v", ir.Status)
	}
}

func TestImmediateRedirectWithCookie_LocationHeader(t *testing.T) {
	// The redirect always targets ghostAdminPath (/ghost/), not the original
	// request path — API paths and OIDC query-params in :path would cause a
	// blank page if echoed back as the redirect target.
	resp := immediateRedirectWithCookie(ghostAdminPath, "ghost-admin-api-session=s:id.sig; Path=/ghost")

	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse")
	}

	var location string
	for _, h := range ir.Headers.GetSetHeaders() {
		if strings.EqualFold(h.Header.Key, "location") {
			location = h.Header.Value
		}
	}
	if location != ghostAdminPath {
		t.Fatalf("location: got %q, want %q", location, ghostAdminPath)
	}
}

func TestImmediateRedirectWithCookie_SetCookieHeader(t *testing.T) {
	srv := testServer()
	cookieVal := srv.buildSetCookieHeader("s:id.sig")
	resp := immediateRedirectWithCookie(ghostAdminPath, cookieVal)

	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse")
	}

	var setCookie string
	for _, h := range ir.Headers.GetSetHeaders() {
		if strings.EqualFold(h.Header.Key, "set-cookie") {
			setCookie = h.Header.Value
		}
	}
	if setCookie != cookieVal {
		t.Fatalf("set-cookie: got %q, want %q", setCookie, cookieVal)
	}
}

func TestImmediateRedirectWithCookie_TwoHeaders(t *testing.T) {
	resp := immediateRedirectWithCookie("/ghost/", "cookie-value")

	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse")
	}
	if len(ir.Headers.GetSetHeaders()) != 2 {
		t.Fatalf("expected 2 headers (location + set-cookie), got %d", len(ir.Headers.GetSetHeaders()))
	}
}

// ─── requestHeadersContinue ───────────────────────────────────────────────────

func TestRequestHeadersContinue_SkipResponsePhase(t *testing.T) {
	resp := requestHeadersContinue(true, nil, nil)

	if resp.ModeOverride == nil {
		t.Fatal("expected ModeOverride to be set when skipResponsePhase=true")
	}
	rh := resp.GetRequestHeaders()
	if rh == nil {
		t.Fatal("expected RequestHeaders response type")
	}
	if rh.Response.Status != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("expected CONTINUE status, got %v", rh.Response.Status)
	}
}

func TestRequestHeadersContinue_AwaitResponsePhase(t *testing.T) {
	resp := requestHeadersContinue(false, nil, nil)

	if resp.ModeOverride != nil {
		t.Fatal("expected ModeOverride to be nil when skipResponsePhase=false")
	}
	rh := resp.GetRequestHeaders()
	if rh == nil {
		t.Fatal("expected RequestHeaders response type")
	}
	if rh.Response.Status != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("expected CONTINUE status, got %v", rh.Response.Status)
	}
}

func TestRequestHeadersContinue_NoMutationWhenNil(t *testing.T) {
	resp := requestHeadersContinue(false, nil, nil)
	rh := resp.GetRequestHeaders()
	if rh.Response.HeaderMutation != nil {
		t.Fatal("expected no HeaderMutation when mutations and removeHeaders are nil")
	}
}

func TestRequestHeadersContinue_RemovesAuthorizationHeader(t *testing.T) {
	resp := requestHeadersContinue(true, nil, []string{"authorization"})
	rh := resp.GetRequestHeaders()
	if rh == nil {
		t.Fatal("expected RequestHeaders response type")
	}
	mut := rh.Response.HeaderMutation
	if mut == nil {
		t.Fatal("expected HeaderMutation when removeHeaders is non-empty")
	}
	if len(mut.RemoveHeaders) != 1 || mut.RemoveHeaders[0] != "authorization" {
		t.Fatalf("expected RemoveHeaders=[authorization], got %v", mut.RemoveHeaders)
	}
}

// ─── appendCookie ─────────────────────────────────────────────────────────────

func TestAppendCookie_EmptyExisting(t *testing.T) {
	got := appendCookie("", "ghost-admin-api-session", "s:id.sig")
	want := "ghost-admin-api-session=s:id.sig"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAppendCookie_WithExisting(t *testing.T) {
	got := appendCookie("IdToken-abc=tok", "ghost-admin-api-session", "s:id.sig")
	want := "IdToken-abc=tok; ghost-admin-api-session=s:id.sig"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// ─── rawHeaderValue ───────────────────────────────────────────────────────────

func TestRawHeaderValue_Found(t *testing.T) {
	headers := []*corev3.HeaderValue{
		{Key: "Cookie", Value: "foo=bar"},
	}
	got := rawHeaderValue(headers, "cookie")
	if got != "foo=bar" {
		t.Fatalf("got %q, want \"foo=bar\"", got)
	}
}

func TestRawHeaderValue_NotFound(t *testing.T) {
	headers := []*corev3.HeaderValue{
		{Key: "Authorization", Value: "Bearer tok"},
	}
	got := rawHeaderValue(headers, "cookie")
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestRawHeaderValue_PathPseudoHeader(t *testing.T) {
	headers := []*corev3.HeaderValue{
		{Key: ":method", Value: "GET"},
		{Key: ":path", Value: "/ghost/api/admin/users/me/?include=roles"},
		{Key: ":authority", Value: "blog.esamir.com"},
	}
	got := rawHeaderValue(headers, ":path")
	if got != "/ghost/api/admin/users/me/?include=roles" {
		t.Fatalf("got %q, want path", got)
	}
}

// ─── responseHeadersContinue ─────────────────────────────────────────────────

func TestResponseHeadersContinue_NoExtraHeaders(t *testing.T) {
	resp := responseHeadersContinue(nil)

	rh := resp.GetResponseHeaders()
	if rh == nil {
		t.Fatal("expected ResponseHeaders response type")
	}
	if rh.Response.Status != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("expected CONTINUE status, got %v", rh.Response.Status)
	}
	if rh.Response.HeaderMutation != nil {
		t.Fatal("expected no HeaderMutation when no extra headers provided")
	}
}

func TestResponseHeadersContinue_EmptySlice(t *testing.T) {
	// An empty (non-nil) slice should also produce no mutation.
	resp := responseHeadersContinue([]*corev3.HeaderValueOption{})
	rh := resp.GetResponseHeaders()
	if rh.Response.HeaderMutation != nil {
		t.Fatal("empty header slice should produce no HeaderMutation")
	}
}
