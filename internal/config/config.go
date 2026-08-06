package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment string
	HTTP        HTTP
	Postgres    Postgres
	Redis       Redis
	Auth        Auth
	RateLimit   RateLimit
}

type HTTP struct {
	Address           string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	RequestTimeout    time.Duration
	MaxHeaderBytes    int
	MaxBodyBytes      int64
	TrustedProxyCIDRs []string
}

type Postgres struct {
	URL             string
	MaxConnections  int32
	MinConnections  int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	HealthTimeout   time.Duration
}

type Redis struct {
	Address       string
	Username      string
	Password      string
	DB            int
	TLS           bool
	DialTimeout   time.Duration
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	PoolSize      int
	HealthTimeout time.Duration
	KeyPrefix     string
}

type Auth struct {
	SessionTTL      time.Duration
	SessionHashKey  []byte
	ArgonMemoryKB   uint32
	ArgonTime       uint32
	ArgonThreads    uint8
	ArgonKeyLength  uint32
	PasswordMin     int
	PasswordMax     int
	HashConcurrency int
}

type RateLimit struct {
	LoginIPLimit       int64
	LoginIdentityLimit int64
	LoginWindow        time.Duration
	RegisterIPLimit    int64
	RegisterWindow     time.Duration
}

const (
	developmentSessionHashKey = "0123456789abcdef0123456789abcdef"
	exampleSessionHashKey     = "replace-with-a-random-secret-of-at-least-32-bytes"
)

func Load() (Config, error) {
	l := &loader{}
	// TODO настроек стало много пока читаю их в одном месте
	cfg := Config{
		Environment: strings.ToLower(strings.TrimSpace(env("APP_ENV", "development"))),
		HTTP: HTTP{
			Address:           strings.TrimSpace(env("HTTP_ADDRESS", ":8080")),
			ReadTimeout:       l.duration("HTTP_READ_TIMEOUT", 10*time.Second),
			ReadHeaderTimeout: l.duration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
			WriteTimeout:      l.duration("HTTP_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:       l.duration("HTTP_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout:   l.duration("HTTP_SHUTDOWN_TIMEOUT", 15*time.Second),
			RequestTimeout:    l.duration("HTTP_REQUEST_TIMEOUT", 5*time.Second),
			MaxHeaderBytes:    l.boundedInteger("HTTP_MAX_HEADER_BYTES", 1<<20, 1024, 16<<20),
			MaxBodyBytes:      int64(l.boundedInteger("HTTP_MAX_BODY_BYTES", 64<<10, 1024, 16<<20)),
			TrustedProxyCIDRs: csv("HTTP_TRUSTED_PROXY_CIDRS"),
		},
		Postgres: Postgres{
			URL:             strings.TrimSpace(env("POSTGRES_URL", "postgres://auth:auth@localhost:5432/auth?sslmode=disable")),
			MaxConnections:  int32(l.boundedInteger("POSTGRES_MAX_CONNECTIONS", 20, 1, 1000)),
			MinConnections:  int32(l.boundedInteger("POSTGRES_MIN_CONNECTIONS", 2, 0, 1000)),
			MaxConnLifetime: l.duration("POSTGRES_MAX_CONN_LIFETIME", 30*time.Minute),
			MaxConnIdleTime: l.duration("POSTGRES_MAX_CONN_IDLE_TIME", 5*time.Minute),
			HealthTimeout:   l.duration("POSTGRES_HEALTH_TIMEOUT", time.Second),
		},
		Redis: Redis{
			Address:       strings.TrimSpace(env("REDIS_ADDRESS", "localhost:6379")),
			Username:      env("REDIS_USERNAME", ""),
			Password:      env("REDIS_PASSWORD", ""),
			DB:            l.boundedInteger("REDIS_DB", 0, 0, 1000),
			TLS:           l.boolean("REDIS_TLS", false),
			DialTimeout:   l.duration("REDIS_DIAL_TIMEOUT", 2*time.Second),
			ReadTimeout:   l.duration("REDIS_READ_TIMEOUT", time.Second),
			WriteTimeout:  l.duration("REDIS_WRITE_TIMEOUT", time.Second),
			PoolSize:      l.boundedInteger("REDIS_POOL_SIZE", 20, 1, 10000),
			HealthTimeout: l.duration("REDIS_HEALTH_TIMEOUT", time.Second),
			KeyPrefix:     strings.TrimSpace(env("REDIS_KEY_PREFIX", "auth:")),
		},
		Auth: Auth{
			SessionTTL:      l.duration("AUTH_SESSION_TTL", 30*time.Minute),
			ArgonMemoryKB:   uint32(l.boundedInteger("AUTH_ARGON2_MEMORY_KB", 19*1024, 8*1024, 256*1024)),
			ArgonTime:       uint32(l.boundedInteger("AUTH_ARGON2_TIME", 2, 1, 10)),
			ArgonThreads:    uint8(l.boundedInteger("AUTH_ARGON2_THREADS", 1, 1, 16)),
			ArgonKeyLength:  uint32(l.boundedInteger("AUTH_ARGON2_KEY_LENGTH", 32, 16, 64)),
			PasswordMin:     l.boundedInteger("AUTH_PASSWORD_MIN_LENGTH", 12, 8, 1024),
			PasswordMax:     l.boundedInteger("AUTH_PASSWORD_MAX_LENGTH", 128, 8, 1024),
			HashConcurrency: l.boundedInteger("AUTH_HASH_CONCURRENCY", 4, 1, 128),
		},
		RateLimit: RateLimit{
			LoginIPLimit:       int64(l.boundedInteger("RATE_LOGIN_IP_LIMIT", 30, 1, 1000000)),
			LoginIdentityLimit: int64(l.boundedInteger("RATE_LOGIN_IDENTITY_LIMIT", 10, 1, 1000000)),
			LoginWindow:        l.duration("RATE_LOGIN_WINDOW", 15*time.Minute),
			RegisterIPLimit:    int64(l.boundedInteger("RATE_REGISTER_IP_LIMIT", 10, 1, 1000000)),
			RegisterWindow:     l.duration("RATE_REGISTER_WINDOW", time.Hour),
		},
	}

	if l.err != nil {
		return Config{}, l.err
	}

	keyText := strings.TrimSpace(os.Getenv("AUTH_SESSION_HASH_KEY"))
	if keyText == "" {
		return Config{}, errors.New("AUTH_SESSION_HASH_KEY is required")
	}
	key, err := decodeSecret(keyText)
	if err != nil {
		return Config{}, fmt.Errorf("AUTH_SESSION_HASH_KEY: %w", err)
	}
	if len(key) < 32 {
		return Config{}, errors.New("AUTH_SESSION_HASH_KEY must contain at least 32 bytes")
	}
	cfg.Auth.SessionHashKey = key

	if cfg.Environment == "" {
		return Config{}, errors.New("APP_ENV must not be empty")
	}
	if cfg.HTTP.Address == "" {
		return Config{}, errors.New("HTTP_ADDRESS is required")
	}
	if cfg.Postgres.URL == "" || cfg.Redis.Address == "" {
		return Config{}, errors.New("POSTGRES_URL and REDIS_ADDRESS are required")
	}
	if cfg.Redis.KeyPrefix == "" || len(cfg.Redis.KeyPrefix) > 128 || strings.ContainsAny(cfg.Redis.KeyPrefix, "\x00\r\n\t ") {
		return Config{}, errors.New("REDIS_KEY_PREFIX must be 1-128 characters without whitespace or control characters")
	}
	if cfg.Postgres.MaxConnections < 1 || cfg.Postgres.MinConnections < 0 || cfg.Postgres.MinConnections > cfg.Postgres.MaxConnections {
		return Config{}, errors.New("invalid PostgreSQL pool configuration")
	}
	if cfg.HTTP.RequestTimeout >= cfg.HTTP.WriteTimeout {
		return Config{}, errors.New("HTTP_REQUEST_TIMEOUT must be less than HTTP_WRITE_TIMEOUT")
	}
	if cfg.Auth.PasswordMin < 8 || cfg.Auth.PasswordMax < cfg.Auth.PasswordMin {
		return Config{}, errors.New("invalid password length configuration")
	}
	if cfg.Auth.SessionTTL < time.Second {
		return Config{}, errors.New("AUTH_SESSION_TTL must be at least 1s")
	}
	if cfg.RateLimit.LoginWindow < time.Second || cfg.RateLimit.RegisterWindow < time.Second {
		return Config{}, errors.New("rate limit windows must be at least 1s")
	}
	if cfg.Auth.ArgonMemoryKB < 8*1024 || cfg.Auth.ArgonMemoryKB > 256*1024 || cfg.Auth.ArgonTime < 1 || cfg.Auth.ArgonTime > 10 || cfg.Auth.ArgonThreads < 1 || cfg.Auth.ArgonThreads > 16 || cfg.Auth.ArgonKeyLength < 16 || cfg.Auth.ArgonKeyLength > 64 {
		return Config{}, errors.New("unsafe Argon2 configuration")
	}
	// TODO не даю запускать прод с тестовым ключом
	if cfg.Environment == "production" {
		if _, ok := os.LookupEnv("POSTGRES_URL"); !ok {
			return Config{}, errors.New("POSTGRES_URL must be set explicitly in production")
		}
		if _, ok := os.LookupEnv("REDIS_ADDRESS"); !ok {
			return Config{}, errors.New("REDIS_ADDRESS must be set explicitly in production")
		}
		if bytes.Equal(cfg.Auth.SessionHashKey, []byte(developmentSessionHashKey)) || bytes.Equal(cfg.Auth.SessionHashKey, []byte(exampleSessionHashKey)) {
			return Config{}, errors.New("AUTH_SESSION_HASH_KEY must not use an example value in production")
		}
	}
	return cfg, nil
}

func decodeSecret(value string) ([]byte, error) {
	// base64 пишу в начале чтобы знать формат ключа
	if strings.HasPrefix(value, "base64:") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "base64:"))
		if err != nil {
			return nil, fmt.Errorf("invalid base64 secret: %w", err)
		}
		return decoded, nil
	}
	return []byte(value), nil
}

func csv(name string) []string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

type loader struct {
	err error
}

func (l *loader) duration(name string, fallback time.Duration) time.Duration {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		l.add(fmt.Errorf("%s must be a positive duration", name))
		return fallback
	}
	return parsed
}

func (l *loader) integer(name string, fallback int) int {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		l.add(fmt.Errorf("%s must be an integer", name))
		return fallback
	}
	return parsed
}

func (l *loader) boundedInteger(name string, fallback, minValue, maxValue int) int {
	value := l.integer(name, fallback)
	if value < minValue || value > maxValue {
		l.add(fmt.Errorf("%s must be between %d and %d", name, minValue, maxValue))
		return fallback
	}
	return value
}

func (l *loader) boolean(name string, fallback bool) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		l.add(fmt.Errorf("%s must be a boolean", name))
		return fallback
	}
	return parsed
}

func (l *loader) add(err error) {
	if l.err == nil {
		l.err = err
		return
	}
	l.err = errors.Join(l.err, err)
}

func LoadPostgresURL() (string, error) {
	value, configured := os.LookupEnv("POSTGRES_URL")
	if !configured {
		if strings.EqualFold(strings.TrimSpace(env("APP_ENV", "development")), "production") {
			return "", errors.New("POSTGRES_URL must be set explicitly in production")
		}
		value = "postgres://auth:auth@localhost:5432/auth?sslmode=disable"
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("POSTGRES_URL is required")
	}
	return value, nil
}
