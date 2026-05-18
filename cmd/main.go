package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/safaci2000/ghost-sso-proxy/config"
	extauthadapter "github.com/safaci2000/ghost-sso-proxy/internal/adapters/primary/extauth"
	"github.com/safaci2000/ghost-sso-proxy/internal/adapters/secondary/mariadb"
	"github.com/safaci2000/ghost-sso-proxy/internal/adapters/secondary/oidctoken"
	"github.com/safaci2000/ghost-sso-proxy/internal/core/service"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		slog.Warn("error loading .env file", "err", err)
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// ── Configuration ─────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// ── Logger ─────────────────────────────────────────────────────────────────
	logLevel := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	logger.Info("ghost-sso-proxy starting",
		slog.String("db_host", cfg.DBHost),
		slog.String("db_name", cfg.DBName),
		slog.Int("grpc_port", cfg.GRPCPort),
	)

	// ── Shared DB connection ───────────────────────────────────────────────────
	db, err := mariadb.Connect(cfg.DSN())
	if err != nil {
		return fmt.Errorf("connecting to MariaDB: %w", err)
	}
	logger.Info("connected to MariaDB")

	// ── Secondary adapters (driven ports) ─────────────────────────────────────
	tokenDecoder := oidctoken.NewDecoder(cfg.OIDCUserInfoURL)
	if cfg.OIDCUserInfoURL != "" {
		logger.Info("OIDC userinfo endpoint configured",
			slog.String("userinfo_url", cfg.OIDCUserInfoURL))
	} else {
		logger.Warn("OIDC_USERINFO_URL not set — falling back to local JWT decode (local dev only)")
	}

	userRepo := mariadb.NewUserRepository(db)

	sessionStore, err := mariadb.NewSessionStore(db, cfg.SessionMaxAgeDays)
	if err != nil {
		return fmt.Errorf("initialising session store: %w", err)
	}
	logger.Info("admin_session_secret loaded for session signing",
		slog.Int("session_max_age_days", cfg.SessionMaxAgeDays))

	// ── Core service ──────────────────────────────────────────────────────────
	authService := service.New(tokenDecoder, userRepo, sessionStore, logger)

	// ── Primary adapter (ExtAuth gRPC server) ─────────────────────────────────
	extauthServer := extauthadapter.NewServer(authService, logger, cfg.SessionMaxAgeDays)

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, extauthServer)
	reflection.Register(grpcServer) // handy for grpcurl debugging

	// Health check — satisfies Kubernetes readiness/liveness probes that use
	// the standard grpc.health.v1.Health protocol.
	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthSrv)
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		return fmt.Errorf("listening on port %d: %w", cfg.GRPCPort, err)
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("gRPC server ready", slog.Int("port", cfg.GRPCPort))
		if err := grpcServer.Serve(lis); err != nil {
			errCh <- fmt.Errorf("gRPC server: %w", err)
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		grpcServer.GracefulStop()
		return <-errCh
	case err := <-errCh:
		return err
	}
}
