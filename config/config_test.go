package config

import (
	"strings"
	"testing"
)

// setEnv temporarily sets env vars for the duration of a test, restoring them after.
func setEnv(t *testing.T, pairs ...string) {
	t.Helper()
	for i := 0; i+1 < len(pairs); i += 2 {
		key, val := pairs[i], pairs[i+1]
		t.Setenv(key, val)
	}
}

// requiredEnv sets the minimum required env vars so Load() does not panic.
func requiredEnv(t *testing.T) {
	t.Helper()
	setEnv(t,
		"DB_USER", "ghost",
		"DB_PASSWORD", "ghostpass",
		"AUTHENTIK_FORWARD_AUTH_URL", "https://auth.example.com/outpost.goauthentik.io/auth/application/ghost-admin/",
	)
}

// ─── Load ─────────────────────────────────────────────────────────────────────

func TestLoad_Defaults(t *testing.T) {
	requiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DBHost != "mariadb.mariadb.svc.cluster.local" {
		t.Errorf("DBHost default: got %q", cfg.DBHost)
	}
	if cfg.DBPort != 3306 {
		t.Errorf("DBPort default: got %d", cfg.DBPort)
	}
	if cfg.DBName != "ghost" {
		t.Errorf("DBName default: got %q", cfg.DBName)
	}
	if cfg.GRPCPort != 8080 {
		t.Errorf("GRPCPort default: got %d", cfg.GRPCPort)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel default: got %q", cfg.LogLevel)
	}
	if cfg.SessionMaxAgeDays != 30 {
		t.Errorf("SessionMaxAgeDays default: got %d, want 30", cfg.SessionMaxAgeDays)
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	setEnv(t,
		"DB_HOST", "127.0.0.1",
		"DB_PORT", "13306",
		"DB_NAME", "mydb",
		"DB_USER", "myuser",
		"DB_PASSWORD", "mypass",
		"GRPC_PORT", "9090",
		"LOG_LEVEL", "debug",
		"SESSION_MAX_AGE_DAYS", "14",
		"AUTHENTIK_FORWARD_AUTH_URL", "https://auth.example.com/outpost.goauthentik.io/auth/application/ghost-admin/",
	)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DBHost != "127.0.0.1" {
		t.Errorf("DBHost: got %q, want 127.0.0.1", cfg.DBHost)
	}
	if cfg.DBPort != 13306 {
		t.Errorf("DBPort: got %d, want 13306", cfg.DBPort)
	}
	if cfg.DBName != "mydb" {
		t.Errorf("DBName: got %q, want mydb", cfg.DBName)
	}
	if cfg.DBUser != "myuser" {
		t.Errorf("DBUser: got %q, want myuser", cfg.DBUser)
	}
	if cfg.DBPassword != "mypass" {
		t.Errorf("DBPassword: got %q, want mypass", cfg.DBPassword)
	}
	if cfg.GRPCPort != 9090 {
		t.Errorf("GRPCPort: got %d, want 9090", cfg.GRPCPort)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel: got %q, want debug", cfg.LogLevel)
	}
	if cfg.SessionMaxAgeDays != 14 {
		t.Errorf("SessionMaxAgeDays: got %d, want 14", cfg.SessionMaxAgeDays)
	}
	if cfg.AuthentikForwardAuthURL != "https://auth.example.com/outpost.goauthentik.io/auth/application/ghost-admin/" {
		t.Errorf("AuthentikForwardAuthURL: got %q", cfg.AuthentikForwardAuthURL)
	}
}

func TestLoad_InvalidDBPort(t *testing.T) {
	requiredEnv(t)
	t.Setenv("DB_PORT", "not-a-number")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid DB_PORT, got nil")
	}
	if !strings.Contains(err.Error(), "DB_PORT") {
		t.Fatalf("error should mention DB_PORT: %v", err)
	}
}

func TestLoad_InvalidGRPCPort(t *testing.T) {
	requiredEnv(t)
	t.Setenv("GRPC_PORT", "bad")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid GRPC_PORT, got nil")
	}
	if !strings.Contains(err.Error(), "GRPC_PORT") {
		t.Fatalf("error should mention GRPC_PORT: %v", err)
	}
}

func TestLoad_AuthentikForwardAuthURL_Required(t *testing.T) {
	// Do NOT set AUTHENTIK_FORWARD_AUTH_URL — Load must panic.
	setEnv(t, "DB_USER", "ghost", "DB_PASSWORD", "ghostpass")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when AUTHENTIK_FORWARD_AUTH_URL is unset")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "AUTHENTIK_FORWARD_AUTH_URL") {
			t.Fatalf("panic message should mention AUTHENTIK_FORWARD_AUTH_URL, got: %v", r)
		}
	}()
	Load() //nolint:errcheck // we expect a panic before Load returns
}

// mustEnv panics when the var is missing — test that via a recover.
func TestMustEnv_PanicsWhenMissing(t *testing.T) {
	// Ensure the key is unset (t.Setenv would restore it after test anyway).
	t.Setenv("__TEST_MUST_ENV_ABSENT__", "")

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for missing required env var")
		}
	}()
	mustEnv("__TEST_MUST_ENV_ABSENT__")
}

func TestMustEnv_ReturnsValue(t *testing.T) {
	t.Setenv("__TEST_MUST_ENV_PRESENT__", "hello")
	got := mustEnv("__TEST_MUST_ENV_PRESENT__")
	if got != "hello" {
		t.Fatalf("expected hello, got %q", got)
	}
}

// ─── DSN ──────────────────────────────────────────────────────────────────────

func TestDSN_Format(t *testing.T) {
	cfg := &Config{
		DBUser:     "ghost",
		DBPassword: "secret",
		DBHost:     "127.0.0.1",
		DBPort:     3306,
		DBName:     "ghost",
	}

	want := "ghost:secret@tcp(127.0.0.1:3306)/ghost?parseTime=true&loc=UTC"
	if got := cfg.DSN(); got != want {
		t.Fatalf("DSN mismatch:\n  got  %q\n  want %q", got, want)
	}
}

func TestDSN_ContainsTCPWrapper(t *testing.T) {
	cfg := &Config{
		DBUser: "u", DBPassword: "p",
		DBHost: "db.example.com", DBPort: 13306, DBName: "mydb",
	}
	dsn := cfg.DSN()
	if !strings.Contains(dsn, "tcp(db.example.com:13306)") {
		t.Fatalf("DSN missing tcp() wrapper: %q", dsn)
	}
}

func TestDSN_ParseTimeAndUTC(t *testing.T) {
	cfg := &Config{DBUser: "u", DBPassword: "p", DBHost: "h", DBPort: 3306, DBName: "d"}
	dsn := cfg.DSN()
	if !strings.Contains(dsn, "parseTime=true") {
		t.Fatalf("DSN missing parseTime=true: %q", dsn)
	}
	if !strings.Contains(dsn, "loc=UTC") {
		t.Fatalf("DSN missing loc=UTC: %q", dsn)
	}
}
