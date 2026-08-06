package config

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	setRequiredEnvironment(t)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Environment != "development" {
		t.Fatalf("unexpected environment: %q", cfg.Environment)
	}
	if cfg.Auth.SessionTTL <= 0 || len(cfg.Auth.SessionHashKey) < 32 {
		t.Fatal("invalid auth defaults")
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   string
		message string
	}{
		{name: "short session key", key: "AUTH_SESSION_HASH_KEY", value: "too-short", message: "at least 32 bytes"},
		{name: "invalid base64", key: "AUTH_SESSION_HASH_KEY", value: "base64:not-base64", message: "invalid base64"},
		{name: "request timeout exceeds write timeout", key: "HTTP_REQUEST_TIMEOUT", value: "20s", message: "less than HTTP_WRITE_TIMEOUT"},
		{name: "subsecond session", key: "AUTH_SESSION_TTL", value: "500ms", message: "at least 1s"},
		{name: "unsafe redis prefix", key: "REDIS_KEY_PREFIX", value: "auth service:", message: "without whitespace"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setRequiredEnvironment(t)
			t.Setenv(test.key, test.value)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected error containing %q, got %v", test.message, err)
			}
		})
	}
}

func TestLoadProductionRequiresExplicitDependencies(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("AUTH_SESSION_HASH_KEY", "base64:"+base64.StdEncoding.EncodeToString([]byte("a-production-only-session-key-32+")))
	unsetEnvironment(t, "POSTGRES_URL")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "POSTGRES_URL") {
		t.Fatalf("expected a production PostgreSQL error, got %v", err)
	}
}

func unsetEnvironment(t *testing.T, name string) {
	t.Helper()
	original, existed := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(name, original)
			return
		}
		_ = os.Unsetenv(name)
	})
}

func TestLoadProductionRejectsDevelopmentSecret(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("POSTGRES_URL", "postgres://auth:auth@postgres:5432/auth?sslmode=require")
	t.Setenv("REDIS_ADDRESS", "redis:6379")
	t.Setenv("AUTH_SESSION_HASH_KEY", developmentSessionHashKey)

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "example value") {
		t.Fatalf("expected an example secret error, got %v", err)
	}
}

func TestLoadPostgresURLRequiresExplicitProductionValue(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	unsetEnvironment(t, "POSTGRES_URL")

	_, err := LoadPostgresURL()
	if err == nil || !strings.Contains(err.Error(), "explicitly") {
		t.Fatalf("expected explicit PostgreSQL URL error, got %v", err)
	}
}

func setRequiredEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("APP_ENV", "development")
	t.Setenv("AUTH_SESSION_HASH_KEY", developmentSessionHashKey)
	// задаю значения сам чтобы тесты не брали их с компьютера
	t.Setenv("POSTGRES_URL", "postgres://auth:auth@localhost:5432/auth?sslmode=disable")
	t.Setenv("REDIS_ADDRESS", "localhost:6379")
}
