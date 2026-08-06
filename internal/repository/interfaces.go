package repository

import (
	"context"
	"time"

	"github.com/acme/auth-service/internal/domain"
)

type UserRepository interface {
	Create(ctx context.Context, email, passwordHash string) (domain.User, error)
	FindByEmail(ctx context.Context, email string) (domain.User, error)
	FindByID(ctx context.Context, id int64) (domain.User, error)
	UpdatePasswordHash(ctx context.Context, id int64, passwordHash string) error
}

type SessionStore interface {
	Create(ctx context.Context, tokenDigest string, userID int64, ttl time.Duration) error
	GetUserID(ctx context.Context, tokenDigest string) (int64, error)
	Delete(ctx context.Context, tokenDigest string) error
}

type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int64, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
	Reset(ctx context.Context, key string) error
}
