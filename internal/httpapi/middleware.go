package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/acme/auth-service/internal/domain"
)

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	userKey      contextKey = "user"
	tokenKey     contextKey = "token"
	routeKey     contextKey = "route"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusRecorder) Written() bool {
	return w.status != 0
}

func requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if id == "" || len(id) > 128 || strings.ContainsAny(id, "\r\n") {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newRequestID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		// TODO если rand не сработал делаю id из времени
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buffer)
}

func requestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

func routeFromContext(ctx context.Context) string {
	value, _ := ctx.Value(routeKey).(string)
	if value == "" {
		return "unmatched"
	}
	return value
}

func withRoute(r *http.Request, route string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), routeKey, route))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// html нет поэтому закрываю лишнее
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func requestTimeout(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error("panic recovered", "panic", recovered, "stack", string(debug.Stack()), "request_id", requestIDFromContext(r.Context()))
					// TODO если ответ уже ушёл могу только записать ошибку
					if state, ok := w.(interface{ Written() bool }); ok && state.Written() {
						return
					}
					writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func accessLog(logger *slog.Logger, metrics *Metrics, clientIPs *ClientIPResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			recorder := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(recorder, r)
			if recorder.status == 0 {
				recorder.status = http.StatusOK
			}
			route := routeFromContext(r.Context())
			duration := time.Since(started)
			metrics.Observe(r.Method, route, recorder.status, duration)
			logger.Info("http request",
				"request_id", requestIDFromContext(r.Context()),
				"method", normalizeMethod(r.Method),
				"route", route,
				"status", recorder.status,
				"duration_ms", duration.Milliseconds(),
				"remote_ip", clientIPs.Resolve(r),
			)
		})
	}
}

func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		user, err := a.auth.Authenticate(r.Context(), token)
		if err != nil {
			if errors.Is(err, domain.ErrInvalidSession) {
				w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
				writeError(w, r, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
				return
			}
			a.logger.Error("authenticate request", "error", err, "request_id", requestIDFromContext(r.Context()))
			if errors.Is(err, domain.ErrUnavailable) {
				writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "authentication service is temporarily unavailable")
			} else {
				writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
			}
			return
		}
		ctx := context.WithValue(r.Context(), userKey, user)
		ctx = context.WithValue(ctx, tokenKey, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(value string) (string, bool) {
	parts := strings.Fields(value)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1], true
	}
	return "", false
}
