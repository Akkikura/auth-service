//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/internal/httpapi"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/repository/redisstore"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
)

const testPassword = "strong-password"

type fixture struct {
	cfg         config.Config
	pool        *pgxpool.Pool
	redisClient *redis.Client
	prefix      string
	server      *httptest.Server
}

func TestAuthScenarios(t *testing.T) {
	f := newFixture(t, time.Minute)

	status, body := requestJSON(t, http.MethodPost, f.server.URL+"/register", map[string]string{"email": "user@example.com", "password": testPassword}, "")
	assertStatus(t, status, http.StatusCreated, body)
	assertNoSecrets(t, body)

	status, body = requestJSON(t, http.MethodPost, f.server.URL+"/register", map[string]string{"email": "bad-email", "password": "short"}, "")
	assertStatus(t, status, http.StatusBadRequest, body)

	status, body = requestJSON(t, http.MethodPost, f.server.URL+"/register", map[string]string{"email": "USER@example.com", "password": testPassword}, "")
	assertStatus(t, status, http.StatusConflict, body)

	status, unknownBody := requestJSON(t, http.MethodPost, f.server.URL+"/login", map[string]string{"email": "missing@example.com", "password": testPassword}, "")
	assertStatus(t, status, http.StatusUnauthorized, unknownBody)
	status, wrongBody := requestJSON(t, http.MethodPost, f.server.URL+"/login", map[string]string{"email": "user@example.com", "password": "wrong-password"}, "")
	assertStatus(t, status, http.StatusUnauthorized, wrongBody)
	if errorSignature(t, unknownBody) != errorSignature(t, wrongBody) {
		t.Fatalf("unknown user and wrong password responses differ: %s / %s", unknownBody, wrongBody)
	}

	status, body = requestJSON(t, http.MethodGet, f.server.URL+"/me", nil, "")
	assertStatus(t, status, http.StatusUnauthorized, body)

	status, body = requestJSON(t, http.MethodPost, f.server.URL+"/login", map[string]string{"email": "user@example.com", "password": testPassword}, "")
	assertStatus(t, status, http.StatusOK, body)
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatal(err)
	}
	if login.Token == "" {
		t.Fatal("missing token")
	}

	status, body = requestJSON(t, http.MethodGet, f.server.URL+"/me", nil, login.Token)
	assertStatus(t, status, http.StatusOK, body)
	assertNoSecrets(t, body)

	status, body = requestJSON(t, http.MethodPost, f.server.URL+"/logout", nil, login.Token)
	assertStatus(t, status, http.StatusNoContent, body)
	status, body = requestJSON(t, http.MethodGet, f.server.URL+"/me", nil, login.Token)
	assertStatus(t, status, http.StatusUnauthorized, body)
}

func TestSessionActuallyExpiresInRedis(t *testing.T) {
	f := newFixture(t, 250*time.Millisecond)
	status, body := requestJSON(t, http.MethodPost, f.server.URL+"/register", map[string]string{"email": "expiry@example.com", "password": testPassword}, "")
	assertStatus(t, status, http.StatusCreated, body)
	status, body = requestJSON(t, http.MethodPost, f.server.URL+"/login", map[string]string{"email": "expiry@example.com", "password": testPassword}, "")
	assertStatus(t, status, http.StatusOK, body)
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		status, body = requestJSON(t, http.MethodGet, f.server.URL+"/me", nil, login.Token)
		if status == http.StatusUnauthorized {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session did not expire, last status %d: %s", status, body)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDependencyFailuresDoNotTerminateProcess(t *testing.T) {
	f := newFixture(t, time.Minute)

	t.Run("postgres unavailable", func(t *testing.T) {
		badPool := newUnavailablePostgresPool(t, f.cfg.Postgres.URL)
		defer badPool.Close()
		server := newServer(t, f.cfg, badPool, f.redisClient, f.prefix+"bad-pg:", time.Minute)
		defer server.Close()

		status, body := requestJSON(t, http.MethodPost, server.URL+"/login", map[string]string{"email": "user@example.com", "password": testPassword}, "")
		assertStatus(t, status, http.StatusServiceUnavailable, body)
		status, body = requestJSON(t, http.MethodGet, server.URL+"/health/live", nil, "")
		assertStatus(t, status, http.StatusOK, body)
	})

	t.Run("redis unavailable", func(t *testing.T) {
		badRedis := redis.NewClient(&redis.Options{
			Addr:         "127.0.0.1:1",
			DialTimeout:  100 * time.Millisecond,
			ReadTimeout:  100 * time.Millisecond,
			WriteTimeout: 100 * time.Millisecond,
			MaxRetries:   0,
		})
		defer func() { _ = badRedis.Close() }()
		server := newServer(t, f.cfg, f.pool, badRedis, f.prefix+"bad-redis:", time.Minute)
		defer server.Close()

		status, body := requestJSON(t, http.MethodPost, server.URL+"/login", map[string]string{"email": "user@example.com", "password": testPassword}, "")
		assertStatus(t, status, http.StatusServiceUnavailable, body)
		status, body = requestJSON(t, http.MethodPost, server.URL+"/register", map[string]string{"email": "redis-down@example.com", "password": testPassword}, "")
		assertStatus(t, status, http.StatusCreated, body)
		status, body = requestJSON(t, http.MethodGet, server.URL+"/health/live", nil, "")
		assertStatus(t, status, http.StatusOK, body)
	})
}

func newFixture(t *testing.T, sessionTTL time.Duration) *fixture {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	adminDB, err := sql.Open("pgx", cfg.Postgres.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adminDB.Close() })
	if err := adminDB.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := randomHex(t, 8)
	schema := "auth_it_" + suffix
	if _, err := adminDB.ExecContext(ctx, `CREATE SCHEMA `+quoteIdentifier(schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = adminDB.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+quoteIdentifier(schema)+` CASCADE`)
	})

	testURL := withSearchPath(t, cfg.Postgres.URL, schema)
	db, err := sql.Open("pgx", testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := migrations.Up(ctx, db); err != nil {
		t.Fatal(err)
	}

	pool, err := pgxpool.New(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	redisClient := newRedisClient(cfg.Redis)
	if err := redisClient.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = redisClient.Close() })
	prefix := cfg.Redis.KeyPrefix + "it:" + suffix + ":"
	t.Cleanup(func() { deleteRedisPrefix(redisClient, prefix) })

	server := newServer(t, cfg, pool, redisClient, prefix, sessionTTL)
	t.Cleanup(server.Close)
	return &fixture{cfg: cfg, pool: pool, redisClient: redisClient, prefix: prefix, server: server}
}

func newServer(t *testing.T, cfg config.Config, pool *pgxpool.Pool, redisClient *redis.Client, prefix string, sessionTTL time.Duration) *httptest.Server {
	t.Helper()
	passwords, err := security.NewPasswordHasher(security.Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := security.NewTokenManager(cfg.Auth.SessionHashKey)
	if err != nil {
		t.Fatal(err)
	}
	metrics := httpapi.NewMetrics()
	auth, err := service.NewAuthService(postgres.NewUserRepository(pool), redisstore.NewSessionStore(redisClient, prefix), passwords, tokens, sessionTTL, 12, 128, 2, metrics)
	if err != nil {
		t.Fatal(err)
	}
	api := httpapi.New(
		auth,
		redisstore.NewRateLimiter(redisClient, prefix),
		httpapi.NewDependencies(pool, redisClient, 200*time.Millisecond, 200*time.Millisecond),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics,
		cfg.RateLimit,
		64<<10,
		2*time.Second,
		mustClientIPs(t),
	)
	return httptest.NewServer(api.Router())
}

func newRedisClient(cfg config.Redis) *redis.Client {
	options := &redis.Options{
		Addr: cfg.Address, Username: cfg.Username, Password: cfg.Password, DB: cfg.DB,
		DialTimeout: cfg.DialTimeout, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout,
		PoolSize: cfg.PoolSize,
	}
	if cfg.TLS {
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return redis.NewClient(options)
}

func newUnavailablePostgresPool(t *testing.T, rawURL string) *pgxpool.Pool {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host := parsed.Hostname()
	if host == "" {
		host = "127.0.0.1"
	}
	parsed.Host = net.JoinHostPort(host, "1")
	cfg, err := pgxpool.ParseConfig(parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.ConnectTimeout = 100 * time.Millisecond
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func withSearchPath(t *testing.T, rawURL, schema string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func deleteRedisPrefix(client *redis.Client, prefix string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cursor uint64
	for {
		keys, next, err := client.Scan(ctx, cursor, prefix+"*", 100).Result()
		if err != nil {
			return
		}
		if len(keys) > 0 {
			_ = client.Del(ctx, keys...).Err()
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}

func requestJSON(t *testing.T, method, target string, payload any, token string) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func assertStatus(t *testing.T, got, want int, body []byte) {
	t.Helper()
	if got != want {
		t.Fatalf("expected %d, got %d: %s", want, got, body)
	}
}

func assertNoSecrets(t *testing.T, body []byte) {
	t.Helper()
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "password") || strings.Contains(lower, "hash") {
		t.Fatalf("response leaks password data: %s", body)
	}
}

func errorSignature(t *testing.T, body []byte) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Error.Code + ":" + envelope.Error.Message
}

func randomHex(t *testing.T, size int) string {
	t.Helper()
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buffer)
}

func quoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func mustClientIPs(t *testing.T) *httpapi.ClientIPResolver {
	t.Helper()
	resolver, err := httpapi.NewClientIPResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}
