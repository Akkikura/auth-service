package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/acme/auth-service/internal/domain"
)

var errUnsupportedMediaType = errors.New("unsupported media type")

type credentialsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string    `json:"token"`
	TokenType string    `json:"token_type"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	var request credentialsRequest
	if err := a.decodeJSON(w, r, &request); err != nil {
		a.writeDecodeError(w, r, err)
		return
	}
	registerLimitKey := "register:ip:" + a.auth.Identifier(a.clientIPs.Resolve(r))
	// TODO пока ограничиваю регистрацию только по IP
	if allowed, retry, err := a.rateLimiter.Allow(r.Context(), registerLimitKey, a.rate.RegisterIPLimit, a.rate.RegisterWindow); err != nil {
		// при ошибке Redis всё равно разрешаю регистрацию
		// база не пропустит одинаковый email
		a.logger.Warn("register rate limit unavailable; proceeding fail-open", "error", err, "request_id", requestIDFromContext(r.Context()))
	} else if !allowed {
		w.Header().Set("Retry-After", retryAfterSeconds(retry))
		writeError(w, r, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}

	user, err := a.auth.Register(r.Context(), request.Email, request.Password)
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, user)
	case errors.Is(err, domain.ErrInvalidInput):
		writeError(w, r, http.StatusBadRequest, "invalid_input", "email or password is invalid")
	case errors.Is(err, domain.ErrEmailAlreadyExists):
		writeError(w, r, http.StatusConflict, "email_exists", "a user with this email already exists")
	case errors.Is(err, domain.ErrUnavailable):
		a.logger.Error("register user", "error", err, "request_id", requestIDFromContext(r.Context()))
		writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "service is temporarily unavailable")
	default:
		a.logger.Error("register user", "error", err, "request_id", requestIDFromContext(r.Context()))
		writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var request credentialsRequest
	if err := a.decodeJSON(w, r, &request); err != nil {
		a.writeDecodeError(w, r, err)
		return
	}

	identityLimitKey := "login:identity:" + a.auth.Identifier(strings.ToLower(strings.TrimSpace(request.Email)))
	// TODO отдельно считаю попытки по IP и по email
	checks := []struct {
		key   string
		limit int64
	}{
		{"login:ip:" + a.auth.Identifier(a.clientIPs.Resolve(r)), a.rate.LoginIPLimit},
		{identityLimitKey, a.rate.LoginIdentityLimit},
	}
	for _, check := range checks {
		allowed, retry, err := a.rateLimiter.Allow(r.Context(), check.key, check.limit, a.rate.LoginWindow)
		if err != nil {
			a.logger.Error("login rate limit", "error", err, "request_id", requestIDFromContext(r.Context()))
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "service is temporarily unavailable")
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", retryAfterSeconds(retry))
			writeError(w, r, http.StatusTooManyRequests, "rate_limited", "too many authentication attempts")
			return
		}
	}

	token, expiresAt, err := a.auth.Login(r.Context(), request.Email, request.Password)
	switch {
	case err == nil:
		// сбрасываю лимит пользователя после входа
		// лимит IP не сбрасываю чтобы не отключать защиту
		if resetErr := a.rateLimiter.Reset(r.Context(), identityLimitKey); resetErr != nil {
			a.logger.Warn("reset login identity rate limit", "error", resetErr, "request_id", requestIDFromContext(r.Context()))
		}
		writeJSON(w, http.StatusOK, loginResponse{Token: token, TokenType: "Bearer", ExpiresAt: expiresAt})
	case errors.Is(err, domain.ErrInvalidCredentials):
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
	case errors.Is(err, domain.ErrUnavailable):
		a.logger.Error("login user", "error", err, "request_id", requestIDFromContext(r.Context()))
		writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "service is temporarily unavailable")
	default:
		a.logger.Error("login user", "error", err, "request_id", requestIDFromContext(r.Context()))
		writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userKey).(domain.PublicUser)
	if !ok {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	token, ok := r.Context().Value(tokenKey).(string)
	if !ok {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if err := a.auth.Logout(r.Context(), token); err != nil {
		a.logger.Error("logout user", "error", err, "request_id", requestIDFromContext(r.Context()))
		if errors.Is(err, domain.ErrUnavailable) {
			writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "service is temporarily unavailable")
		} else {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return errUnsupportedMediaType
	}
	r.Body = http.MaxBytesReader(w, r.Body, a.maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	// TODO второй Decode ловит лишний JSON
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func retryAfterSeconds(duration time.Duration) string {
	seconds := int64((duration + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10)
}

func (a *API) writeDecodeError(w http.ResponseWriter, r *http.Request, err error) {
	var maxBytesError *http.MaxBytesError
	switch {
	case errors.Is(err, errUnsupportedMediaType):
		writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
	case errors.As(err, &maxBytesError):
		writeError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
	default:
		writeError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
	}
}
