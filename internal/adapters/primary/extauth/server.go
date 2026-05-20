// Package extauth implements the primary (driving) adapter: an Envoy External
// Authorization gRPC service. Envoy calls it for every request on the ghost-admin
// HTTPRoute via a SecurityPolicy extAuth block.
//
// Flow per HTTP request (one unary Check RPC):
//
//  1. ExtAuth.Check is called with all request headers.
//  2. The Authentik forward auth client checks whether the browser's Authentik
//     proxy session cookie is valid.
//     — Authentik 302: user not logged in → DeniedResponse 302 to Authentik login.
//     — Authentik 200 + email: user authenticated → proceed to step 3.
//     — Error: fail-open (OkResponse); Ghost's own login page is a safe fallback.
//  3. If a ghost-admin-api-session cookie is already present → OkResponse (fast path).
//  4. Otherwise: create/reuse a Ghost DB session → DeniedResponse 302 to /ghost/
//     with Set-Cookie. The browser stores the cookie and retries; the retry hits
//     the fast path in step 3.
//
// Why DeniedResponse for the redirect: Envoy Gateway strips Set-Cookie from
// OkResponse header mutations. A DeniedResponse bypasses the response-filter
// chain entirely, so Set-Cookie reaches the browser unmodified.
package extauth

import (
	"context"
	"fmt"
	"log/slog"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/csg33k/ghost-sso-proxy/internal/core/ports/primary"
	"github.com/csg33k/ghost-sso-proxy/internal/core/ports/secondary"
)

const (
	ghostSessionCookieName = "ghost-admin-api-session"

	// ghostAdminPath is the canonical redirect target after planting the session
	// cookie. We always redirect here rather than echoing the original :path —
	// API sub-paths in :path would cause a blank page or a secondary redirect loop.
	ghostAdminPath = "/ghost/"

	// cookieMaxAge is the default Max-Age for the injected session cookie in
	// seconds (180 days). This is only used in unit tests; production code reads
	// the value from cfg.SessionMaxAgeDays via Server.sessionMaxAgeSecs.
	cookieMaxAge = 180 * 24 * 60 * 60 // 15552000 seconds
)

// Server implements authv3.AuthorizationServer.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	auth              primary.AuthService
	authentik         secondary.ForwardAuthChecker
	logger            *slog.Logger
	sessionMaxAgeSecs int // Max-Age for the Set-Cookie header, in seconds
}

// NewServer constructs a Server driven by the provided AuthService and
// ForwardAuthChecker. sessionMaxAgeDays should come from cfg.SessionMaxAgeDays
// so the cookie lifetime tracks the SESSION_MAX_AGE_DAYS environment variable.
func NewServer(auth primary.AuthService, authentik secondary.ForwardAuthChecker, logger *slog.Logger, sessionMaxAgeDays int) *Server {
	return &Server{
		auth:              auth,
		authentik:         authentik,
		logger:            logger,
		sessionMaxAgeSecs: sessionMaxAgeDays * 24 * 60 * 60,
	}
}

// Check handles one ExtAuth RPC (= one HTTP request).
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	cookieHeader := headers["cookie"]

	// Extract forwarding fields for Authentik. Envoy sends HTTP/2 pseudo-headers
	// (:authority, :scheme, :path) for all requests regardless of protocol.
	host := firstNonEmpty(headers[":authority"], headers["host"])
	proto := firstNonEmpty(headers[":scheme"], headers["x-forwarded-proto"])
	uri := headers[":path"]

	s.logger.DebugContext(ctx, "extauth check",
		slog.Bool("has_cookie_header", cookieHeader != ""),
		slog.String("host", host),
		slog.String("proto", proto),
		slog.String("uri", uri),
	)

	// ── Step 1: Authentik forward auth ───────────────────────────────────────
	email, redirectURL, authentikCookies, err := s.authentik.Check(ctx, cookieHeader, host, proto, uri)
	if err != nil {
		s.logger.WarnContext(ctx, "authentik forward auth error, failing open",
			slog.Any("error", err))
		return okResponse(), nil
	}

	if redirectURL != "" {
		// Not authenticated — bounce the browser to Authentik's login flow.
		// Forward any Set-Cookie headers from Authentik (PKCE state cookies)
		// so the OAuth2 callback can complete. Without them the callback returns
		// "invalid state" and the login loop never finishes.
		s.logger.DebugContext(ctx, "authentik redirect, not authenticated",
			slog.String("location", redirectURL),
			slog.Int("proxy_cookies", len(authentikCookies)))
		return deniedRedirectTo(redirectURL, authentikCookies), nil
	}

	// ── Step 2: ensure a Ghost session exists for this user ──────────────────
	signedCookie, err := s.auth.EnsureSession(ctx, cookieHeader, email)
	if err != nil {
		s.logger.WarnContext(ctx, "auth service error, failing open",
			slog.Any("error", err))
		return okResponse(), nil
	}

	if signedCookie == "" {
		// Fast path: Ghost session cookie already present. Pass through.
		return okResponse(), nil
	}

	// Slow path: no Ghost session cookie yet. Issue a 302 redirect to /ghost/
	// with Set-Cookie so the browser stores the cookie and retries. On retry
	// the cookie is present and the fast path fires.
	//
	// We always redirect to /ghost/ rather than echoing :path because :path may
	// be a Ghost API endpoint called by the SPA — redirecting there returns JSON,
	// which the browser renders as a blank page instead of the admin UI.
	cookieVal := s.buildSetCookieHeader(signedCookie)
	s.logger.InfoContext(ctx, "issuing cookie-set redirect",
		slog.String("redirect_target", ghostAdminPath),
		slog.String("email", email))
	return deniedRedirectWithCookie(ghostAdminPath, cookieVal), nil
}

// ─── Response builders ────────────────────────────────────────────────────────

// okResponse returns a CheckResponse that allows the request to proceed.
func okResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &statuspb.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{},
		},
	}
}

// deniedRedirectTo returns a CheckResponse that sends a 302 redirect to the
// given URL — used to forward the browser to Authentik's login flow.
// setCookies is the list of raw Set-Cookie header values from Authentik's 302
// response (e.g. authentik_proxy_* PKCE state cookies); each is forwarded
// as its own Set-Cookie response header so the browser stores the state token
// needed to complete the OAuth2 callback.
func deniedRedirectTo(url string, setCookies []string) *authv3.CheckResponse {
	hdrs := make([]*corev3.HeaderValueOption, 0, 1+len(setCookies))
	hdrs = append(hdrs, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   "location",
			Value: url,
		},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	})
	for _, cookie := range setCookies {
		hdrs = append(hdrs, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   "set-cookie",
				Value: cookie,
			},
			AppendAction: corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
		})
	}
	return &authv3.CheckResponse{
		Status: &statuspb.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Found},
				Headers: hdrs,
			},
		},
	}
}

// deniedRedirectWithCookie returns a CheckResponse that short-circuits the
// request and sends a 302 redirect directly to the browser with a Set-Cookie
// header. Envoy delivers DeniedResponse bodies without running them through the
// response-header filter chain, so Set-Cookie reaches the browser unmodified.
func deniedRedirectWithCookie(path, cookieValue string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &statuspb.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Found},
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "location",
							Value: path,
						},
						AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
					},
					{
						Header: &corev3.HeaderValue{
							Key:   "set-cookie",
							Value: cookieValue,
						},
						AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
					},
				},
			},
		},
	}
}

// buildSetCookieHeader formats the Set-Cookie header value for the ghost session.
// SameSite=None is required to match Ghost's own session cookie so that the
// browser sends it on cross-origin admin API requests the Ghost SPA makes.
// SameSite=None mandates Secure=true, which we always include.
func (s *Server) buildSetCookieHeader(signedCookieValue string) string {
	return fmt.Sprintf(
		"%s=%s; Path=/ghost; HttpOnly; Secure; SameSite=None; Max-Age=%d",
		ghostSessionCookieName, signedCookieValue, s.sessionMaxAgeSecs,
	)
}

// firstNonEmpty returns the first non-empty string from vals.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
