package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	// DB connection parameters for the Ghost MariaDB database.
	// The shim uses the same credentials as Ghost itself.
	DBHost     string
	DBPort     int
	DBName     string
	DBUser     string
	DBPassword string

	// GRPCPort is the port the ExtAuth gRPC server listens on (default 8080).
	GRPCPort int

	// LogLevel controls slog verbosity: "debug", "info", "warn", "error".
	LogLevel string

	// SessionMaxAgeDays controls the lifetime of the Ghost admin session cookie
	// and the session_data.cookie.originalMaxAge written to the DB.
	// Shorter values are fine — when the Ghost session expires Authentik's
	// forward auth re-issues a new one transparently (no user login prompt).
	// Defaults to 30 days.
	SessionMaxAgeDays int

	// AuthentikForwardAuthURL is the Authentik proxyv2 forward auth endpoint.
	// The ExtAuth adapter forwards browser Cookie and X-Forwarded-* headers here;
	// Authentik validates its proxy session and returns X-Authentik-Email (200)
	// or a redirect to its login flow (302).
	// Use the /auth/traefik path — the per-application path was removed in 2026.x.
	// Example: https://auth.example.com/outpost.goauthentik.io/auth/traefik
	// Required — the service panics at startup if this is not set.
	AuthentikForwardAuthURL string
}

// Load reads configuration from environment variables.
// Required variables: DB_USER, DB_PASSWORD, AUTHENTIK_FORWARD_AUTH_URL.
func Load() (*Config, error) {
	cfg := &Config{
		DBHost:                  env("DB_HOST", "mariadb.mariadb.svc.cluster.local"),
		DBName:                  env("DB_NAME", "ghost"),
		DBUser:                  mustEnv("DB_USER"),
		DBPassword:              mustEnv("DB_PASSWORD"),
		LogLevel:                env("LOG_LEVEL", "info"),
		AuthentikForwardAuthURL: mustEnv("AUTHENTIK_FORWARD_AUTH_URL"),
	}

	var err error
	cfg.DBPort, err = strconv.Atoi(env("DB_PORT", "3306"))
	if err != nil {
		return nil, fmt.Errorf("config: invalid DB_PORT: %w", err)
	}
	cfg.GRPCPort, err = strconv.Atoi(env("GRPC_PORT", "8080"))
	if err != nil {
		return nil, fmt.Errorf("config: invalid GRPC_PORT: %w", err)
	}
	cfg.SessionMaxAgeDays, err = strconv.Atoi(env("SESSION_MAX_AGE_DAYS", "30"))
	if err != nil {
		return nil, fmt.Errorf("config: invalid SESSION_MAX_AGE_DAYS: %w", err)
	}
	if cfg.SessionMaxAgeDays <= 0 {
		return nil, fmt.Errorf("config: SESSION_MAX_AGE_DAYS must be > 0, got %d", cfg.SessionMaxAgeDays)
	}
	return cfg, nil
}

// DSN returns a go-sql-driver/mysql data source name.
func (c *Config) DSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("config: required environment variable %q is not set", key))
	}
	return v
}
