// Package extproc implements the primary (driving) adapter: an Envoy External
// Processor gRPC service. Envoy calls it for every request on the ghost-admin
// HTTPRoute via an EnvoyExtensionPolicy.
//
// Flow per HTTP request (one bidirectional gRPC stream):
//
//  1. ProcessingRequest_RequestHeaders arrives.
//     — Call AuthService.EnsureSession with the request headers.
//     — If a ghost-admin-api-session cookie already exists → CONTINUE, tell
//       Envoy to skip the response-header phase (ModeOverride SKIP).
//     — If a new signed cookie value is returned → send an ImmediateResponse
//       302 redirect to /ghost/ with Set-Cookie. The browser stores the
//       cookie and retries; the retry hits the fast path above.
//     — On any error → log and pass through; Ghost renders its own login page.
//
//  Note: Envoy Gateway strips Set-Cookie from ExtProc response-header mutations
//  and does not apply ExtProc upstream request Cookie mutations to the forwarded
//  request. The ImmediateResponse redirect is the only reliable delivery path.
package extproc

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
	"github.com/safaci2000/ghost-sso-proxy/internal/core/ports/primary"
)

const (
	ghostSessionCookieName = "ghost-admin-api-session"

	// ghostAdminPath is the canonical redirect target after planting the session
	// cookie. We always redirect here rather than echoing back the original
	// :path — see the slow-path comment in Process() for the full rationale.
	ghostAdminPath = "/ghost/"

	// cookieMaxAge is the default Max-Age for the injected session cookie in
	// seconds (180 days). This is only used in unit tests; production code reads
	// the value from cfg.SessionMaxAgeDays via Server.sessionMaxAgeSecs.
	cookieMaxAge = 180 * 24 * 60 * 60 // 15552000 seconds
)

// Server implements extprocv3.ExternalProcessorServer.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
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

// Process handles one bidirectional ExtProc gRPC stream (= one HTTP request).
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("extproc: recv: %w", err)
		}

		switch v := req.Request.(type) {

		case *extprocv3.ProcessingRequest_RequestHeaders:
			headers := v.RequestHeaders.GetHeaders().GetHeaders()
			cookieHeader := rawHeaderValue(headers, "cookie")
			authHeader := rawHeaderValue(headers, "authorization")
			signedCookie, err := s.auth.EnsureSession(
				stream.Context(),
				cookieHeader,
				authHeader,
			)
			if err != nil {
				// On any auth error, log and pass through. Ghost's own login
				// page is a safe fallback; we never hard-block a request.
				level := slog.LevelWarn
				if errors.Is(err, domain.ErrNoToken) {
					// Expected during the /oauth2/callback round-trip — not a real error.
					level = slog.LevelDebug
				}
				s.logger.Log(stream.Context(), level, "auth service error, passing through",
					slog.Any("error", err))
				if err := stream.Send(requestHeadersContinue(true, nil, []string{"authorization"})); err != nil {
					return fmt.Errorf("extproc: send (pass-through): %w", err)
				}
				continue
			}

			if signedCookie == "" {
				// Session cookie already present — skip response-header processing.
				// Strip the Authorization: Bearer header injected by Envoy's
				// forwardAccessToken so it never reaches Ghost.
				if err := stream.Send(requestHeadersContinue(true, nil, []string{"authorization"})); err != nil {
					return fmt.Errorf("extproc: send (skip response): %w", err)
				}
			} else {
				// No ghost session cookie in the browser yet. Issue a 302 redirect
				// to /ghost/ with Set-Cookie so the browser stores the cookie and
				// retries the request. On retry the cookie is present and the fast
				// path fires, forwarding directly to Ghost.
				//
				// We always redirect to /ghost/ rather than echoing back the
				// original :path for two reasons:
				//   1. The :path may be a Ghost API endpoint (e.g. /ghost/api/admin/…)
				//      triggered by the SPA — redirecting there returns JSON, which
				//      the browser renders as a blank page instead of the admin UI.
				//   2. The :path may carry Envoy OIDC state query-parameters that
				//      confuse Ghost or cause a secondary redirect loop.
				// Envoy's OIDC filter already restored the user to the correct URL
				// before our ExtProc was invoked; our only job here is to plant the
				// cookie so the next request reaches Ghost authenticated.
				//
				// Envoy Gateway strips Set-Cookie from the ExtProc response-headers
				// phase and does not honour upstream Cookie mutations from ExtProc,
				// so an ImmediateResponse is the only reliable delivery mechanism.
				cookieHeader := s.buildSetCookieHeader(signedCookie)
				s.logger.InfoContext(stream.Context(), "issuing cookie-set redirect",
					slog.String("redirect_target", ghostAdminPath))
				if err := stream.Send(immediateRedirectWithCookie(ghostAdminPath, cookieHeader)); err != nil {
					return fmt.Errorf("extproc: send (cookie redirect): %w", err)
				}
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			// With the redirect approach the fast path sets ModeOverride=SKIP and
			// the slow path returns ImmediateResponse, so this phase should never
			// fire. Pass through as a no-op if it arrives unexpectedly.
			s.logger.WarnContext(stream.Context(), "unexpected response-headers phase; passing through")
			if err := stream.Send(responseHeadersContinue(nil)); err != nil {
				return fmt.Errorf("extproc: send (response pass-through): %w", err)
			}
		}
	}
}

// ─── Response builders ────────────────────────────────────────────────────────

// immediateRedirectWithCookie returns a ProcessingResponse that short-circuits
// the proxied request and sends a 302 redirect directly to the browser with a
// Set-Cookie header. Envoy delivers ImmediateResponse bodies without running
// them through the response-header filter chain, so the Set-Cookie reaches the
// browser unmodified — unlike the ExtProc response-headers mutation path.
func immediateRedirectWithCookie(path, cookieValue string) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{
					Code: typev3.StatusCode_Found, // 302
				},
				Headers: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						{
							Header: &corev3.HeaderValue{
								Key:   "location",
								Value: path,
							},
							// ExtProc filters must explicitly set OVERWRITE_IF_EXISTS_OR_ADD.
							// Without it Envoy Gateway delivers the header with an empty value.
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
		},
	}
}

// requestHeadersContinue returns a ProcessingResponse that continues the request.
// When skipResponsePhase is true, a ModeOverride tells Envoy not to send
// response headers to our ExtProc, saving a round-trip on the fast path.
// requestMutations (optional) are applied to the upstream request headers.
// removeHeaders (optional) lists header names to strip before Envoy forwards
// the request — used to prevent the Envoy-injected "Authorization: Bearer"
// access token from leaking to Ghost.
func requestHeadersContinue(skipResponsePhase bool, requestMutations []*corev3.HeaderValueOption, removeHeaders []string) *extprocv3.ProcessingResponse {
	common := &extprocv3.CommonResponse{
		Status: extprocv3.CommonResponse_CONTINUE,
	}
	if len(requestMutations) > 0 || len(removeHeaders) > 0 {
		common.HeaderMutation = &extprocv3.HeaderMutation{
			SetHeaders:    requestMutations,
			RemoveHeaders: removeHeaders,
		}
	}
	resp := &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{
				Response: common,
			},
		},
	}
	if skipResponsePhase {
		resp.ModeOverride = &filterv3.ProcessingMode{
			ResponseHeaderMode: filterv3.ProcessingMode_SKIP,
		}
	}
	return resp
}

// responseHeadersContinue returns a ProcessingResponse that continues the response,
// optionally mutating headers.
func responseHeadersContinue(extraHeaders []*corev3.HeaderValueOption) *extprocv3.ProcessingResponse {
	common := &extprocv3.CommonResponse{
		Status: extprocv3.CommonResponse_CONTINUE,
	}
	if len(extraHeaders) > 0 {
		common.HeaderMutation = &extprocv3.HeaderMutation{
			SetHeaders: extraHeaders,
		}
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{
				Response: common,
			},
		},
	}
}

// rawHeaderValue returns the value of the first header matching name
// (case-insensitive), preferring RawValue over Value.
func rawHeaderValue(headers []*corev3.HeaderValue, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.GetKey(), name) {
			if raw := h.GetRawValue(); len(raw) > 0 {
				return string(raw)
			}
			return h.GetValue()
		}
	}
	return ""
}

// appendCookie appends name=value to an existing Cookie header string.
// If existing is empty the result is just the new pair; otherwise a "; "
// separator is inserted so the resulting header remains valid.
func appendCookie(existing, name, value string) string {
	entry := name + "=" + value
	if existing == "" {
		return entry
	}
	return existing + "; " + entry
}

// buildSetCookieHeader formats the Set-Cookie header value for the ghost session.
// SameSite=None is required to match Ghost's own session cookie so that the
// browser sends it on the cross-origin admin API requests the Ghost SPA makes.
// SameSite=None mandates Secure=true, which we always include.
func (s *Server) buildSetCookieHeader(signedCookieValue string) string {
	return fmt.Sprintf(
		"%s=%s; Path=/ghost; HttpOnly; Secure; SameSite=None; Max-Age=%d",
		ghostSessionCookieName, signedCookieValue, s.sessionMaxAgeSecs,
	)
}
