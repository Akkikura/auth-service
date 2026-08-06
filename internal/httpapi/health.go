package httpapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type Dependencies struct {
	postgres        *pgxpool.Pool
	redis           *redis.Client
	postgresTimeout time.Duration
	redisTimeout    time.Duration
}

func NewDependencies(postgres *pgxpool.Pool, redisClient *redis.Client, postgresTimeout, redisTimeout time.Duration) *Dependencies {
	return &Dependencies{postgres: postgres, redis: redisClient, postgresTimeout: postgresTimeout, redisTimeout: redisTimeout}
}

func (d *Dependencies) Ready(ctx context.Context) error {
	// TODO буфер чтобы обе проверки могли записать ответ
	results := make(chan error, 2)
	go func() { results <- d.pingPostgres(ctx) }()
	go func() { results <- d.pingRedis(ctx) }()

	var failures []error
	for range 2 {
		if err := <-results; err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (d *Dependencies) pingPostgres(ctx context.Context) error {
	postgresCtx, cancelPostgres := context.WithTimeout(ctx, d.postgresTimeout)
	defer cancelPostgres()
	if err := d.postgres.Ping(postgresCtx); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	return nil
}

func (d *Dependencies) pingRedis(ctx context.Context) error {
	redisCtx, cancelRedis := context.WithTimeout(ctx, d.redisTimeout)
	defer cancelRedis()
	if err := d.redis.Ping(redisCtx).Err(); err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	return nil
}
