package extproc

import (
	"fmt"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// ─── buildSetCookieHeader ─────────────────────────────────────────────────────

func TestBuildSetCookieHeader_Format(t *testing.T) {
	signed := "s:myID.hmacSig"
	got := buildSetCookieHeader(signed)

	want := fmt.Sprintf(
		"ghost-admin-api-session=%s; Path=/ghost; HttpOnly; Secure; SameSite=Lax; Max-Age=%d",
		signed, cookieMaxAge,
	)
	if got != want {
		t.Fatalf("Set-Cookie header mismatch:\n  got  %q\n  want %q", got, want)
	}
}

func TestBuildSetCookieHeader_ContainsRequiredAttributes(t *testing.T) {
	got := buildSetCookieHeader("s:id.sig")

	required := []string{"HttpOnly", "Secure", "SameSite=Lax", "Path=/ghost", "Max-Age="}
	for _, attr := range required {
		if !strings.Contains(got, attr) {
			t.Errorf("Set-Cookie header missing %q: %q", attr, got)
		}
	}
}

func TestBuildSetCookieHeader_MaxAge(t *testing.T) {
	if cookieMaxAge != 86400 {
		t.Fatalf("expected cookieMaxAge=86400, got %d", cookieMaxAge)
	}
	got := buildSetCookieHeader("s:id.sig")
	if !strings.Contains(got, "Max-Age=86400") {
		t.Fatalf("expected Max-Age=86400 in %q", got)
	}
}

// ─── requestHeadersContinue ───────────────────────────────────────────────────

func TestRequestHeadersContinue_SkipResponsePhase(t *testing.T) {
	resp := requestHeadersContinue(true)

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
	resp := requestHeadersContinue(false)

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

func TestResponseHeadersContinue_WithSetCookie(t *testing.T) {
	extra := []*corev3.HeaderValueOption{{
		Header: &corev3.HeaderValue{
			Key:   "Set-Cookie",
			Value: "ghost-admin-api-session=s:id.sig; Path=/ghost",
		},
	}}
	resp := responseHeadersContinue(extra)

	rh := resp.GetResponseHeaders()
	if rh == nil {
		t.Fatal("expected ResponseHeaders response type")
	}
	if rh.Response.HeaderMutation == nil {
		t.Fatal("expected HeaderMutation to be set when extra headers provided")
	}
	if len(rh.Response.HeaderMutation.SetHeaders) != 1 {
		t.Fatalf("expected 1 header in mutation, got %d", len(rh.Response.HeaderMutation.SetHeaders))
	}
	gotKey := rh.Response.HeaderMutation.SetHeaders[0].Header.Key
	if gotKey != "Set-Cookie" {
		t.Fatalf("expected Set-Cookie header, got %q", gotKey)
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
