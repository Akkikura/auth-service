package redisstore

import (
	"context"
	"fmt"
	"time"

	"github.com/acme/auth-service/internal/domain"
	"github.com/redis/go-redis/v9"
)

// TODO Lua нужен чтобы счётчик и время жизни ставились вместе
var rateLimitScript = redis.NewScript(`
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
return {current, ttl}
`)

type RateLimiter struct {
	client *redis.Client
	prefix string
}

func NewRateLimiter(client *redis.Client, prefix string) *RateLimiter {
	return &RateLimiter{client: client, prefix: prefix + "rate:"}
}

func (l *RateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, time.Duration, error) {
	result, err := rateLimitScript.Run(ctx, l.client, []string{l.prefix + key}, window.Milliseconds()).Result()
	if err != nil {
		return false, 0, fmt.Errorf("%w: rate limit: %w", domain.ErrUnavailable, err)
	}
	values, ok := result.([]interface{})
	if !ok || len(values) != 2 {
		return false, 0, fmt.Errorf("rate limit: unexpected Redis response")
	}
	current, ok := values[0].(int64)
	if !ok {
		return false, 0, fmt.Errorf("rate limit: invalid counter")
	}
	ttlMS, ok := values[1].(int64)
	if !ok {
		return false, 0, fmt.Errorf("rate limit: invalid ttl")
	}
	if ttlMS < 0 {
		// TODO при -1 беру полное окно чтобы не сломать Retry After
		ttlMS = window.Milliseconds()
	}
	return current <= limit, time.Duration(ttlMS) * time.Millisecond, nil
}

func (l *RateLimiter) Reset(ctx context.Context, key string) error {
	if err := l.client.Del(ctx, l.prefix+key).Err(); err != nil {
		return fmt.Errorf("%w: reset rate limit: %w", domain.ErrUnavailable, err)
	}
	return nil
}
