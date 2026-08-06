package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/acme/auth-service/internal/domain"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/security"
)

type RehashObserver interface {
	PasswordRehashFailed(error)
}

type RehashObserverFunc func(error)

func (f RehashObserverFunc) PasswordRehashFailed(err error) {
	if f != nil {
		f(err)
	}
}

type AuthService struct {
	users          repository.UserRepository
	sessions       repository.SessionStore
	passwords      *security.PasswordHasher
	tokens         *security.TokenManager
	sessionTTL     time.Duration
	passwordMin    int
	passwordMax    int
	dummyHash      string
	passwordSlots  chan struct{}
	rehashObserver RehashObserver
}

func NewAuthService(
	users repository.UserRepository,
	sessions repository.SessionStore,
	passwords *security.PasswordHasher,
	tokens *security.TokenManager,
	sessionTTL time.Duration,
	passwordMin int,
	passwordMax int,
	hashConcurrency int,
	rehashObserver RehashObserver,
) (*AuthService, error) {
	if users == nil || sessions == nil || passwords == nil || tokens == nil {
		return nil, errors.New("auth service dependencies are required")
	}
	if sessionTTL <= 0 || passwordMin < 8 || passwordMax < passwordMin || hashConcurrency < 1 {
		return nil, errors.New("invalid auth service configuration")
	}
	// TODO этот хеш скрывает есть пользователь или нет
	dummyHash, err := passwords.Hash("dummy-password-used-only-for-timing")
	if err != nil {
		return nil, fmt.Errorf("create dummy password hash: %w", err)
	}
	return &AuthService{
		users: users, sessions: sessions, passwords: passwords, tokens: tokens,
		sessionTTL: sessionTTL, passwordMin: passwordMin, passwordMax: passwordMax, dummyHash: dummyHash,
		passwordSlots: make(chan struct{}, hashConcurrency), rehashObserver: rehashObserver,
	}, nil
}

func (s *AuthService) Register(ctx context.Context, email, password string) (domain.PublicUser, error) {
	normalized, err := normalizeAndValidateEmail(email)
	if err != nil || !s.validPassword(password) {
		return domain.PublicUser{}, domain.ErrInvalidInput
	}
	hash, err := s.hashPassword(ctx, password)
	if err != nil {
		return domain.PublicUser{}, fmt.Errorf("hash password: %w", err)
	}
	user, err := s.users.Create(ctx, normalized, hash)
	if err != nil {
		return domain.PublicUser{}, err
	}
	return user.Public(), nil
}

func (s *AuthService) Login(ctx context.Context, email, password string) (string, time.Time, error) {
	normalized, validationErr := normalizeAndValidateEmail(email)
	if validationErr != nil || utf8.RuneCountInString(password) == 0 || utf8.RuneCountInString(password) > s.passwordMax {
		// TODO сначала проверяю dummyHash и потом отдаю ошибку
		if _, err := s.verifyPassword(ctx, "invalid-password", s.dummyHash); err != nil {
			return "", time.Time{}, err
		}
		return "", time.Time{}, domain.ErrInvalidCredentials
	}

	user, err := s.users.FindByEmail(ctx, normalized)
	if errors.Is(err, domain.ErrUserNotFound) {
		if _, verifyErr := s.verifyPassword(ctx, password, s.dummyHash); verifyErr != nil {
			return "", time.Time{}, verifyErr
		}
		return "", time.Time{}, domain.ErrInvalidCredentials
	}
	if err != nil {
		return "", time.Time{}, err
	}
	valid, err := s.verifyPassword(ctx, password, user.PasswordHash)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("verify password: %w", err)
	}
	if !valid {
		return "", time.Time{}, domain.ErrInvalidCredentials
	}

	if s.passwords.NeedsRehash(user.PasswordHash) {
		// TODO новый хеш делаю сразу потому что в фоне ошибки терялись
		if newHash, hashErr := s.hashPassword(ctx, password); hashErr != nil {
			s.observeRehashFailure(fmt.Errorf("hash replacement password: %w", hashErr))
		} else if updateErr := s.users.UpdatePasswordHash(ctx, user.ID, newHash); updateErr != nil {
			s.observeRehashFailure(updateErr)
		}
	}

	raw, digest, err := s.tokens.Generate()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generate session token: %w", err)
	}
	if err := s.sessions.Create(ctx, digest, user.ID, s.sessionTTL); err != nil {
		return "", time.Time{}, err
	}
	return raw, time.Now().UTC().Add(s.sessionTTL), nil
}

func (s *AuthService) Authenticate(ctx context.Context, rawToken string) (domain.PublicUser, error) {
	if !s.tokens.ValidFormat(rawToken) {
		return domain.PublicUser{}, domain.ErrInvalidSession
	}
	userID, err := s.sessions.GetUserID(ctx, s.tokens.Digest(rawToken))
	if err != nil {
		return domain.PublicUser{}, err
	}
	user, err := s.users.FindByID(ctx, userID)
	if errors.Is(err, domain.ErrUserNotFound) {
		return domain.PublicUser{}, domain.ErrInvalidSession
	}
	if err != nil {
		return domain.PublicUser{}, err
	}
	return user.Public(), nil
}

func (s *AuthService) Logout(ctx context.Context, rawToken string) error {
	if !s.tokens.ValidFormat(rawToken) {
		return domain.ErrInvalidSession
	}
	return s.sessions.Delete(ctx, s.tokens.Digest(rawToken))
}

func (s *AuthService) Identifier(value string) string {
	return s.tokens.Identifier(value)
}

func (s *AuthService) validPassword(password string) bool {
	length := utf8.RuneCountInString(password)
	return length >= s.passwordMin && length <= s.passwordMax && strings.TrimSpace(password) != ""
}

func normalizeAndValidateEmail(value string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(value))
	if email == "" || len(email) > 254 || strings.ContainsAny(email, "\r\n") {
		return "", domain.ErrInvalidInput
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || !strings.Contains(email, "@") {
		return "", domain.ErrInvalidInput
	}
	return email, nil
}

type hashResult struct {
	value string
	err   error
}

func (s *AuthService) hashPassword(ctx context.Context, password string) (string, error) {
	if err := s.acquirePasswordSlot(ctx); err != nil {
		return "", err
	}
	// TODO буфер нужен чтобы горутина не зависла после таймаута
	result := make(chan hashResult, 1)
	go func() {
		defer s.releasePasswordSlot()
		value, err := s.passwords.Hash(password)
		result <- hashResult{value: value, err: err}
	}()

	select {
	case completed := <-result:
		return completed.value, completed.err
	case <-ctx.Done():
		return "", fmt.Errorf("%w: password hashing canceled: %w", domain.ErrUnavailable, ctx.Err())
	}
}

type verifyResult struct {
	valid bool
	err   error
}

func (s *AuthService) verifyPassword(ctx context.Context, password, encoded string) (bool, error) {
	if err := s.acquirePasswordSlot(ctx); err != nil {
		return false, err
	}
	result := make(chan verifyResult, 1)
	go func() {
		defer s.releasePasswordSlot()
		valid, err := s.passwords.Verify(password, encoded)
		result <- verifyResult{valid: valid, err: err}
	}()

	select {
	case completed := <-result:
		return completed.valid, completed.err
	case <-ctx.Done():
		return false, fmt.Errorf("%w: password verification canceled: %w", domain.ErrUnavailable, ctx.Err())
	}
}

func (s *AuthService) acquirePasswordSlot(ctx context.Context) error {
	select {
	case s.passwordSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%w: password hashing capacity: %w", domain.ErrUnavailable, ctx.Err())
	}
}

func (s *AuthService) releasePasswordSlot() {
	<-s.passwordSlots
}

func (s *AuthService) observeRehashFailure(err error) {
	if s.rehashObserver != nil {
		s.rehashObserver.PasswordRehashFailed(err)
	}
}
