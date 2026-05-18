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

	// GRPCPort is the port the ExtProc gRPC server listens on (default 8080).
	GRPCPort int

	// LogLevel controls slog verbosity: "debug", "info", "warn", "error".
	LogLevel string
}

// Load reads configuration from environment variables.
// Required variables: DB_USER, DB_PASSWORD.
func Load() (*Config, error) {
	cfg := &Config{
		DBHost:     env("DB_HOST", "mariadb.mariadb.svc.cluster.local"),
		DBName:     env("DB_NAME", "ghost"),
		DBUser:     mustEnv("DB_USER"),
		DBPassword: mustEnv("DB_PASSWORD"),
		LogLevel:   env("LOG_LEVEL", "info"),
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
