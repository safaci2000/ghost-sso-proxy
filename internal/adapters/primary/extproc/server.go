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
//     — If a new signed cookie value is returned → store it in stream-local
//       state, CONTINUE (response-header phase will fire).
//     — On any error → log and pass through; Ghost renders its own login page.
//
//  2. ProcessingRequest_ResponseHeaders arrives (only when step 1 flagged it).
//     — Mutate the response by adding Set-Cookie with the signed cookie value.
//     — The browser stores the cookie; the Ghost SPA boots already authenticated.
package extproc

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
	"github.com/safaci2000/ghost-sso-proxy/internal/core/ports/primary"
)

const (
	ghostSessionCookieName = "ghost-admin-api-session"
	// cookieMaxAge is the Max-Age we set on the injected cookie (24 h).
	// Ghost itself treats sessions as browser-session cookies, but setting
	// Max-Age makes the cookie survive browser restarts for convenience.
	cookieMaxAge = 86400
)

// Server implements extprocv3.ExternalProcessorServer.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
	auth   primary.AuthService
	logger *slog.Logger
}

// NewServer constructs a Server driven by the provided AuthService.
func NewServer(auth primary.AuthService, logger *slog.Logger) *Server {
	return &Server{auth: auth, logger: logger}
}

// Process handles one bidirectional ExtProc gRPC stream (= one HTTP request).
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	// pendingCookie is non-empty when we need to inject Set-Cookie in the response phase.
	var pendingCookie string

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
			signedCookie, err := s.auth.EnsureSession(
				stream.Context(),
				v.RequestHeaders.GetHeaders().GetHeaders(),
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
				if err := stream.Send(requestHeadersContinue(true)); err != nil {
					return fmt.Errorf("extproc: send (pass-through): %w", err)
				}
				continue
			}

			if signedCookie == "" {
				// Session cookie already present — skip response-header processing.
				if err := stream.Send(requestHeadersContinue(true)); err != nil {
					return fmt.Errorf("extproc: send (skip response): %w", err)
				}
			} else {
				// New session created — store cookie value for response phase.
				pendingCookie = signedCookie
				if err := stream.Send(requestHeadersContinue(false)); err != nil {
					return fmt.Errorf("extproc: send (await response): %w", err)
				}
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			if pendingCookie == "" {
				if err := stream.Send(responseHeadersContinue(nil)); err != nil {
					return fmt.Errorf("extproc: send (response pass-through): %w", err)
				}
				continue
			}

			cookieValue := buildSetCookieHeader(pendingCookie)
			pendingCookie = "" // consume

			injection := []*corev3.HeaderValueOption{{
				Header: &corev3.HeaderValue{
					Key:   "Set-Cookie",
					Value: cookieValue,
				},
			}}
			s.logger.DebugContext(stream.Context(), "injecting ghost session cookie")
			if err := stream.Send(responseHeadersContinue(injection)); err != nil {
				return fmt.Errorf("extproc: send (inject cookie): %w", err)
			}
		}
	}
}

// ─── Response builders ────────────────────────────────────────────────────────

// requestHeadersContinue returns a ProcessingResponse that continues the request.
// When skipResponsePhase is true, a ModeOverride tells Envoy not to send
// response headers to our ExtProc, saving a round-trip on the fast path.
func requestHeadersContinue(skipResponsePhase bool) *extprocv3.ProcessingResponse {
	resp := &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{
				Response: &extprocv3.CommonResponse{
					Status: extprocv3.CommonResponse_CONTINUE,
				},
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
// optionally mutating headers (used to inject Set-Cookie).
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

// buildSetCookieHeader formats the Set-Cookie header value for the ghost session.
func buildSetCookieHeader(signedCookieValue string) string {
	return fmt.Sprintf(
		"%s=%s; Path=/ghost; HttpOnly; Secure; SameSite=Lax; Max-Age=%d",
		ghostSessionCookieName, signedCookieValue, cookieMaxAge,
	)
}
