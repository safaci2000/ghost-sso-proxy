// Package extauth implements the primary (driving) adapter: an Envoy External
// Authorization gRPC service. Envoy calls it for every request on the ghost-admin
// HTTPRoute via a SecurityPolicy extAuth block.
//
// Flow per HTTP request (one unary Check RPC):
//
//  1. The OIDC filter in the SecurityPolicy runs first, authenticates with
//     Authentik, and injects "Authorization: Bearer <jwt>" via forwardAccessToken.
//  2. ExtAuth.Check is called with all request headers.
//     — If a ghost-admin-api-session cookie already exists → OkResponse.
//       Strip the Authorization header so it never reaches Ghost.
//     — If a new signed cookie value is returned → DeniedResponse 302 to
//       /ghost/ with Set-Cookie. The browser stores the cookie and retries;
//       the retry hits the fast path above.
//     — On any error → OkResponse (fail-open). Ghost renders its own login page
//       as a safe fallback; we never hard-block a request.
//
//  Why DeniedResponse for the redirect: Envoy Gateway strips Set-Cookie from
//  OkResponse header mutations. A DeniedResponse bypasses the response-filter
//  chain entirely, so Set-Cookie is delivered to the browser unmodified.
package extauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
	"github.com/safaci2000/ghost-sso-proxy/internal/core/ports/primary"
)

const (
	ghostSessionCookieName = "ghost-admin-api-session"

	// ghostAdminPath is the canonical redirect target after planting the session
	// cookie. We always redirect here rather than echoing the original :path —
	// API sub-paths and OIDC query-params in :path would cause a blank page or
	// a secondary redirect loop.
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
	logger            *slog.Logger
	sessionMaxAgeSecs int // Max-Age for the Set-Cookie header, in seconds
}

// NewServer constructs a Server driven by the provided AuthService.
// sessionMaxAgeDays should come from cfg.SessionMaxAgeDays so the cookie
// lifetime tracks the SESSION_MAX_AGE_DAYS environment variable.
func NewServer(auth primary.AuthService, logger *slog.Logger, sessionMaxAgeDays int) *Server {
	return &Server{
		auth:              auth,
		logger:            logger,
		sessionMaxAgeSecs: sessionMaxAgeDays * 24 * 60 * 60,
	}
}

// Check handles one ExtAuth RPC (= one HTTP request).
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	cookieHeader := headers["cookie"]
	authHeader := extractAuthHeader(req)

	// Log a full diagnostic snapshot at DEBUG. This intentionally dumps header
	// names (not values) and metadata namespace keys so we can diagnose filter-
	// chain ordering and metadata_context_namespaces issues without leaking tokens.
	if s.logger.Enabled(ctx, slog.LevelDebug) {
		// Collect request header names.
		hdrNames := make([]string, 0, len(headers))
		for k := range headers {
			hdrNames = append(hdrNames, k)
		}
		// Collect metadata context namespace keys.
		var metaKeys []string
		if filterMeta := req.GetAttributes().GetMetadataContext().GetFilterMetadata(); filterMeta != nil {
			for k := range filterMeta {
				metaKeys = append(metaKeys, k)
			}
		}
		// Surface the raw oauth2 metadata fields if the namespace is present.
		var oauth2Fields []string
		if filterMeta := req.GetAttributes().GetMetadataContext().GetFilterMetadata(); filterMeta != nil {
			if s, ok := filterMeta["envoy.filters.http.oauth2"]; ok && s != nil {
				for k := range s.GetFields() {
					oauth2Fields = append(oauth2Fields, k)
				}
			}
		}
		s.logger.DebugContext(ctx, "extauth check",
			slog.Bool("has_bearer_token", strings.HasPrefix(authHeader, "Bearer ")),
			slog.String("auth_source", authSource(req)),
			slog.Bool("has_cookie_header", cookieHeader != ""),
			slog.Any("request_header_names", hdrNames),
			slog.Any("metadata_namespaces", metaKeys),
			slog.Any("oauth2_metadata_fields", oauth2Fields),
		)
	}

	signedCookie, err := s.auth.EnsureSession(ctx, cookieHeader, authHeader)
	if err != nil {
		// On any auth error, log and fail open. Ghost's own login page is a
		// safe fallback; we never hard-block a request.
		level := slog.LevelWarn
		if errors.Is(err, domain.ErrNoToken) {
			// Expected during the /oauth2/callback round-trip — not a real error.
			level = slog.LevelDebug
		}
		s.logger.Log(ctx, level, "auth service error, failing open", slog.Any("error", err))
		return okResponse([]string{"authorization"}), nil
	}

	if signedCookie == "" {
		// Fast path: session cookie already present. Pass through, stripping the
		// Authorization header so the Bearer token never reaches Ghost.
		return okResponse([]string{"authorization"}), nil
	}

	// Slow path: no ghost session cookie yet. Issue a 302 redirect to /ghost/
	// with Set-Cookie so the browser stores the cookie and retries. On retry
	// the cookie is present and the fast path fires.
	//
	// We always redirect to /ghost/ rather than echoing :path for two reasons:
	//   1. :path may be a Ghost API endpoint (e.g. /ghost/api/admin/…) called
	//      by the SPA — redirecting there returns JSON, which the browser
	//      renders as a blank page instead of the admin UI.
	//   2. :path may carry Envoy OIDC state query-parameters that confuse Ghost
	//      or cause a secondary redirect loop.
	cookieVal := s.buildSetCookieHeader(signedCookie)
	s.logger.InfoContext(ctx, "issuing cookie-set redirect",
		slog.String("redirect_target", ghostAdminPath))
	return deniedRedirectWithCookie(ghostAdminPath, cookieVal), nil
}

// ─── Response builders ────────────────────────────────────────────────────────

// okResponse returns a CheckResponse that allows the request to proceed.
// headersToRemove lists headers to strip before the request reaches the upstream
// — used to prevent the Envoy-injected "Authorization: Bearer" token from
// leaking to Ghost.
func okResponse(headersToRemove []string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &statuspb.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				HeadersToRemove: headersToRemove,
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
				Status: &typev3.HttpStatus{
					Code: typev3.StatusCode_Found, // 302
				},
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

// extractAuthHeader returns the best available "Authorization: Bearer <token>"
// string for this request.
//
// Preference order:
//  1. The Authorization header injected by an upstream filter (e.g. if Envoy
//     ever wires forwardAccessToken into ExtAuth's view of the request).
//  2. The raw access token from the Envoy oauth2 filter's dynamic metadata —
//     the standard production path. Envoy writes the decrypted access token
//     under metadata_context["envoy.filters.http.oauth2"]["access_token"]
//     before calling ExtAuth.
//
// Returns "" when neither source has a token (no OIDC session yet / first leg
// of the OIDC redirect dance).
func extractAuthHeader(req *authv3.CheckRequest) string {
	// Try the Authorization header first.
	if h := req.GetAttributes().GetRequest().GetHttp().GetHeaders()["authorization"]; strings.HasPrefix(h, "Bearer ") {
		return h
	}

	// Fall back to Envoy oauth2 filter metadata.
	// GetFilterMetadata() returns nil when there is no metadata — all Get* calls
	// are nil-safe on protobuf generated types.
	filterMeta := req.GetAttributes().GetMetadataContext().GetFilterMetadata()
	if filterMeta == nil {
		return ""
	}
	oauthStruct, ok := filterMeta["envoy.filters.http.oauth2"]
	if !ok || oauthStruct == nil {
		return ""
	}
	fields := oauthStruct.GetFields()
	if fields == nil {
		return ""
	}
	tokenVal, ok := fields["access_token"]
	if !ok || tokenVal == nil {
		return ""
	}
	if token := tokenVal.GetStringValue(); token != "" {
		return "Bearer " + token
	}
	return ""
}

// authSource returns a short string identifying where the auth token came from,
// for debug logging.
func authSource(req *authv3.CheckRequest) string {
	if h := req.GetAttributes().GetRequest().GetHttp().GetHeaders()["authorization"]; strings.HasPrefix(h, "Bearer ") {
		return "authorization_header"
	}
	filterMeta := req.GetAttributes().GetMetadataContext().GetFilterMetadata()
	if filterMeta != nil {
		if oauthStruct, ok := filterMeta["envoy.filters.http.oauth2"]; ok && oauthStruct != nil {
			if fields := oauthStruct.GetFields(); fields != nil {
				if v, ok := fields["access_token"]; ok && v.GetStringValue() != "" {
					return "oauth2_filter_metadata"
				}
			}
		}
	}
	return "none"
}
