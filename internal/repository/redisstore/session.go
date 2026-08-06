package redisstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/acme/auth-service/internal/domain"
	"github.com/redis/go-redis/v9"
)

type SessionStore struct {
	client *redis.Client
	prefix string
}

func NewSessionStore(client *redis.Client, prefix string) *SessionStore {
	return &SessionStore{client: client, prefix: prefix + "session:"}
}

func (s *SessionStore) Create(ctx context.Context, tokenDigest string, userID int64, ttl time.Duration) error {
	// храню хеш токена чтобы сам токен не попал в Redis
	if err := s.client.Set(ctx, s.prefix+tokenDigest, userID, ttl).Err(); err != nil {
		return fmt.Errorf("%w: create session: %w", domain.ErrUnavailable, err)
	}
	return nil
}

func (s *SessionStore) GetUserID(ctx context.Context, tokenDigest string) (int64, error) {
	value, err := s.client.Get(ctx, s.prefix+tokenDigest).Result()
	if errors.Is(err, redis.Nil) {
		return 0, domain.ErrInvalidSession
	}
	if err != nil {
		return 0, fmt.Errorf("%w: get session: %w", domain.ErrUnavailable, err)
	}
	// TODO ID читаю как строку потому что Redis так его отдаёт
	userID, err := strconv.ParseInt(value, 10, 64)
	if err != nil || userID <= 0 {
		return 0, domain.ErrInvalidSession
	}
	return userID, nil
}

func (s *SessionStore) Delete(ctx context.Context, tokenDigest string) error {
	if err := s.client.Del(ctx, s.prefix+tokenDigest).Err(); err != nil {
		return fmt.Errorf("%w: delete session: %w", domain.ErrUnavailable, err)
	}
	return nil
}
