package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/internal/domain"
	"github.com/acme/auth-service/internal/repository"
)

type Auth interface {
	Register(ctx context.Context, email, password string) (domain.PublicUser, error)
	Login(ctx context.Context, email, password string) (string, time.Time, error)
	Authenticate(ctx context.Context, rawToken string) (domain.PublicUser, error)
	Logout(ctx context.Context, rawToken string) error
	Identifier(value string) string
}

type HealthChecker interface {
	Ready(ctx context.Context) error
}

type API struct {
	auth           Auth
	rateLimiter    repository.RateLimiter
	health         HealthChecker
	logger         *slog.Logger
	metrics        *Metrics
	rate           config.RateLimit
	maxBodyBytes   int64
	requestTimeout time.Duration
	clientIPs      *ClientIPResolver
}

func New(
	auth Auth,
	rateLimiter repository.RateLimiter,
	health HealthChecker,
	logger *slog.Logger,
	metrics *Metrics,
	rate config.RateLimit,
	maxBodyBytes int64,
	timeout time.Duration,
	clientIPs *ClientIPResolver,
) *API {
	return &API{
		auth: auth, rateLimiter: rateLimiter, health: health, logger: logger,
		metrics: metrics, rate: rate, maxBodyBytes: maxBodyBytes, requestTimeout: timeout, clientIPs: clientIPs,
	}
}

func (a *API) Router() http.Handler {
	var handler http.Handler = http.HandlerFunc(a.dispatch)
	// оборачиваю в обратном порядке потому что так работают middleware
	handler = recoverer(a.logger)(handler)
	handler = accessLog(a.logger, a.metrics, a.clientIPs)(handler)
	handler = requestTimeout(a.requestTimeout)(handler)
	handler = securityHeaders(handler)
	handler = requestContext(handler)
	return handler
}

func (a *API) dispatch(w http.ResponseWriter, r *http.Request) {
	// TODO пока хватает обычного switch без отдельного роутера
	route := routeForPath(r.URL.Path)
	*r = *withRoute(r, route)
	switch r.URL.Path {
	case "/health/live":
		a.method(w, r, http.MethodGet, a.live)
	case "/health/ready":
		a.method(w, r, http.MethodGet, a.ready)
	case "/metrics":
		a.method(w, r, http.MethodGet, a.metrics.ServeHTTP)
	case "/register":
		a.method(w, r, http.MethodPost, a.register)
	case "/login":
		a.method(w, r, http.MethodPost, a.login)
	case "/me":
		a.method(w, r, http.MethodGet, a.authenticate(http.HandlerFunc(a.me)).ServeHTTP)
	case "/logout":
		a.method(w, r, http.MethodPost, a.authenticate(http.HandlerFunc(a.logout)).ServeHTTP)
	default:
		writeError(w, r, http.StatusNotFound, "not_found", "resource not found")
	}
}

func routeForPath(path string) string {
	switch path {
	case "/health/live", "/health/ready", "/metrics", "/register", "/login", "/me", "/logout":
		return path
	default:
		return "unmatched"
	}
}

func (a *API) method(w http.ResponseWriter, r *http.Request, expected string, handler http.HandlerFunc) {
	if r.Method != expected {
		w.Header().Set("Allow", expected)
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	handler(w, r)
}

func (a *API) live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) ready(w http.ResponseWriter, r *http.Request) {
	if err := a.health.Ready(r.Context()); err != nil {
		a.logger.Warn("readiness check failed", "error", err)
		writeError(w, r, http.StatusServiceUnavailable, "not_ready", "service is not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
