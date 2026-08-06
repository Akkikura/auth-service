package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/internal/domain"
)

type fakeAuth struct {
	registerUser domain.PublicUser
	registerErr  error
	loginToken   string
	loginExpiry  time.Time
	loginErr     error
	meUser       domain.PublicUser
	meErr        error
	logoutErr    error
	panicOnMe    bool
}

func (f *fakeAuth) Register(context.Context, string, string) (domain.PublicUser, error) {
	return f.registerUser, f.registerErr
}
func (f *fakeAuth) Login(context.Context, string, string) (string, time.Time, error) {
	return f.loginToken, f.loginExpiry, f.loginErr
}
func (f *fakeAuth) Authenticate(context.Context, string) (domain.PublicUser, error) {
	if f.panicOnMe {
		panic("test panic")
	}
	return f.meUser, f.meErr
}
func (f *fakeAuth) Logout(context.Context, string) error { return f.logoutErr }
func (f *fakeAuth) Identifier(value string) string       { return "id:" + value }

type allowAllLimiter struct {
	allowed  bool
	err      error
	resetErr error
	onReset  func(string)
}

func (l allowAllLimiter) Allow(context.Context, string, int64, time.Duration) (bool, time.Duration, error) {
	return l.allowed, time.Minute, l.err
}

func (l allowAllLimiter) Reset(_ context.Context, key string) error {
	if l.onReset != nil {
		l.onReset(key)
	}
	return l.resetErr
}

type fakeHealth struct{ err error }

func (h fakeHealth) Ready(context.Context) error { return h.err }

func newTestAPI(auth Auth, limiter allowAllLimiter, health fakeHealth) *API {
	resolver, err := NewClientIPResolver(nil)
	if err != nil {
		panic(err)
	}
	return New(
		auth,
		limiter,
		health,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		NewMetrics(),
		config.RateLimit{
			LoginIPLimit: 10, LoginIdentityLimit: 10, LoginWindow: time.Minute,
			RegisterIPLimit: 10, RegisterWindow: time.Minute,
		},
		64<<10,
		2*time.Second,
		resolver,
	)
}

func TestRegisterReturnsCreatedWithoutSecrets(t *testing.T) {
	createdAt := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	api := newTestAPI(&fakeAuth{registerUser: domain.PublicUser{ID: 1, Email: "user@example.com", CreatedAt: createdAt}}, allowAllLimiter{allowed: true}, fakeHealth{})

	response := performJSON(t, api.Router(), http.MethodPost, "/register", `{"email":"user@example.com","password":"strong-password"}`, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d: %s", http.StatusCreated, response.Code, response.Body.String())
	}
	body := response.Body.String()
	if strings.Contains(body, "password") || strings.Contains(body, "hash") {
		t.Fatalf("response leaks password data: %s", body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected no-store cache policy")
	}
}

func TestRegisterRejectsUnknownJSONField(t *testing.T) {
	api := newTestAPI(&fakeAuth{}, allowAllLimiter{allowed: true}, fakeHealth{})
	response := performJSON(t, api.Router(), http.MethodPost, "/register", `{"email":"user@example.com","password":"strong-password","admin":true}`, "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, response.Code)
	}
	assertErrorCode(t, response, "invalid_request")
}

func TestRegisterRejectsUnsupportedMediaType(t *testing.T) {
	api := newTestAPI(&fakeAuth{}, allowAllLimiter{allowed: true}, fakeHealth{})
	request := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(`{"email":"user@example.com","password":"strong-password"}`))
	request.Header.Set("Content-Type", "text/plain")
	response := httptest.NewRecorder()
	api.Router().ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected %d, got %d", http.StatusUnsupportedMediaType, response.Code)
	}
	assertErrorCode(t, response, "unsupported_media_type")
}

func TestRegisterRejectsOversizedBody(t *testing.T) {
	resolver, err := NewClientIPResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	api := New(
		&fakeAuth{}, allowAllLimiter{allowed: true}, fakeHealth{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), NewMetrics(),
		config.RateLimit{RegisterIPLimit: 10, RegisterWindow: time.Minute, LoginIPLimit: 10, LoginIdentityLimit: 10, LoginWindow: time.Minute},
		32, 2*time.Second, resolver,
	)
	response := performJSON(t, api.Router(), http.MethodPost, "/register", `{"email":"user@example.com","password":"strong-password"}`, "")
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected %d, got %d: %s", http.StatusRequestEntityTooLarge, response.Code, response.Body.String())
	}
	assertErrorCode(t, response, "request_too_large")
}

func TestDuplicateEmailIsConflict(t *testing.T) {
	api := newTestAPI(&fakeAuth{registerErr: domain.ErrEmailAlreadyExists}, allowAllLimiter{allowed: true}, fakeHealth{})
	response := performJSON(t, api.Router(), http.MethodPost, "/register", `{"email":"user@example.com","password":"strong-password"}`, "")
	if response.Code != http.StatusConflict {
		t.Fatalf("expected %d, got %d", http.StatusConflict, response.Code)
	}
	assertErrorCode(t, response, "email_exists")
}

func TestRegisterRateLimiterFailsOpen(t *testing.T) {
	api := newTestAPI(
		&fakeAuth{registerUser: domain.PublicUser{ID: 1, Email: "user@example.com"}},
		allowAllLimiter{err: errors.New("redis unavailable")},
		fakeHealth{},
	)
	response := performJSON(t, api.Router(), http.MethodPost, "/register", `{"email":"user@example.com","password":"strong-password"}`, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d: %s", http.StatusCreated, response.Code, response.Body.String())
	}
}

func TestSuccessfulLoginResetsIdentityLimit(t *testing.T) {
	var resetKey string
	api := newTestAPI(
		&fakeAuth{loginToken: "token", loginExpiry: time.Now().Add(time.Minute)},
		allowAllLimiter{allowed: true, onReset: func(key string) { resetKey = key }},
		fakeHealth{},
	)
	response := performJSON(t, api.Router(), http.MethodPost, "/login", `{"email":"User@Example.com","password":"strong-password"}`, "")
	if response.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d: %s", http.StatusOK, response.Code, response.Body.String())
	}
	if !strings.HasPrefix(resetKey, "login:identity:") {
		t.Fatalf("identity rate limit was not reset: %q", resetKey)
	}
}

func TestLoginUsesGenericUnauthorizedResponse(t *testing.T) {
	api := newTestAPI(&fakeAuth{loginErr: domain.ErrInvalidCredentials}, allowAllLimiter{allowed: true}, fakeHealth{})
	response := performJSON(t, api.Router(), http.MethodPost, "/login", `{"email":"missing@example.com","password":"wrong-password"}`, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, response.Code)
	}
	assertErrorCode(t, response, "invalid_credentials")
	if !strings.Contains(response.Body.String(), "invalid email or password") {
		t.Fatalf("expected generic credentials message: %s", response.Body.String())
	}
}

func TestLoginRateLimitReturnsRetryAfter(t *testing.T) {
	api := newTestAPI(&fakeAuth{}, allowAllLimiter{allowed: false}, fakeHealth{})
	response := performJSON(t, api.Router(), http.MethodPost, "/login", `{"email":"user@example.com","password":"strong-password"}`, "")
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("expected %d, got %d: %s", http.StatusTooManyRequests, response.Code, response.Body.String())
	}
	if response.Header().Get("Retry-After") != "60" {
		t.Fatalf("unexpected Retry-After header: %q", response.Header().Get("Retry-After"))
	}
	assertErrorCode(t, response, "rate_limited")
}

func TestMeRequiresBearerToken(t *testing.T) {
	api := newTestAPI(&fakeAuth{}, allowAllLimiter{allowed: true}, fakeHealth{})
	response := performJSON(t, api.Router(), http.MethodGet, "/me", "", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, response.Code)
	}
	assertErrorCode(t, response, "unauthorized")
}

func TestMeReturnsAuthenticatedUser(t *testing.T) {
	api := newTestAPI(&fakeAuth{meUser: domain.PublicUser{ID: 42, Email: "user@example.com"}}, allowAllLimiter{allowed: true}, fakeHealth{})
	response := performJSON(t, api.Router(), http.MethodGet, "/me", "", "valid-token")
	if response.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d: %s", http.StatusOK, response.Code, response.Body.String())
	}
	var user domain.PublicUser
	if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}
	if user.ID != 42 || user.Email != "user@example.com" {
		t.Fatalf("unexpected user: %+v", user)
	}
}

func TestExpiredSessionIsUnauthorized(t *testing.T) {
	api := newTestAPI(&fakeAuth{meErr: domain.ErrInvalidSession}, allowAllLimiter{allowed: true}, fakeHealth{})
	response := performJSON(t, api.Router(), http.MethodGet, "/me", "", "expired-token")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, response.Code)
	}
}

func TestPanicReturnsJSONErrorAndIsRecorded(t *testing.T) {
	api := newTestAPI(&fakeAuth{panicOnMe: true}, allowAllLimiter{allowed: true}, fakeHealth{})
	response := performJSON(t, api.Router(), http.MethodGet, "/me", "", "valid-token")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d, got %d: %s", http.StatusInternalServerError, response.Code, response.Body.String())
	}
	assertErrorCode(t, response, "internal_error")
	if response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("panic response is missing security headers")
	}

	metrics := httptest.NewRecorder()
	api.metrics.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), `route="/me",status="500"} 1`) {
		t.Fatalf("panic response was not recorded as 500: %s", metrics.Body.String())
	}
}

func TestDependencyFailuresReturnServiceUnavailable(t *testing.T) {
	t.Run("redis rate limiter", func(t *testing.T) {
		api := newTestAPI(&fakeAuth{}, allowAllLimiter{err: errors.New("redis unavailable")}, fakeHealth{})
		response := performJSON(t, api.Router(), http.MethodPost, "/login", `{"email":"user@example.com","password":"strong-password"}`, "")
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, response.Code)
		}
	})

	t.Run("postgres auth", func(t *testing.T) {
		api := newTestAPI(&fakeAuth{loginErr: domain.ErrUnavailable}, allowAllLimiter{allowed: true}, fakeHealth{})
		response := performJSON(t, api.Router(), http.MethodPost, "/login", `{"email":"user@example.com","password":"strong-password"}`, "")
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, response.Code)
		}
	})
}

func TestReadinessReflectsDependencies(t *testing.T) {
	api := newTestAPI(&fakeAuth{}, allowAllLimiter{allowed: true}, fakeHealth{err: errors.New("database down")})
	response := performJSON(t, api.Router(), http.MethodGet, "/health/ready", "", "")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, response.Code)
	}
}

func TestWrongMethodReturnsAllowHeader(t *testing.T) {
	api := newTestAPI(&fakeAuth{}, allowAllLimiter{allowed: true}, fakeHealth{})
	response := performJSON(t, api.Router(), http.MethodGet, "/register", "", "")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d, got %d", http.StatusMethodNotAllowed, response.Code)
	}
	if response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("unexpected Allow header: %q", response.Header().Get("Allow"))
	}
}

func performJSON(t *testing.T, handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.RemoteAddr = "192.0.2.10:54321"
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertErrorCode(t *testing.T, response *httptest.ResponseRecorder, expected string) {
	t.Helper()
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != expected {
		t.Fatalf("expected error code %q, got %q", expected, envelope.Error.Code)
	}
}
