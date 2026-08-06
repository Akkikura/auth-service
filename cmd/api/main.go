package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/internal/httpapi"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/repository/redisstore"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).With("service", "auth-service")
	cfg, err := config.Load()
	if err != nil {
		logger.Error("load configuration", "error", err)
		os.Exit(1)
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.Postgres.URL)
	if err != nil {
		logger.Error("parse PostgreSQL configuration", "error", err)
		os.Exit(1)
	}
	poolConfig.MaxConns = cfg.Postgres.MaxConnections
	poolConfig.MinConns = cfg.Postgres.MinConnections
	poolConfig.MaxConnLifetime = cfg.Postgres.MaxConnLifetime
	poolConfig.MaxConnIdleTime = cfg.Postgres.MaxConnIdleTime
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	// по этому имени вижу соединения сервиса в postgres
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "auth-service"
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		logger.Error("create PostgreSQL pool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	redisOptions := &redis.Options{
		Addr: cfg.Redis.Address, Username: cfg.Redis.Username, Password: cfg.Redis.Password, DB: cfg.Redis.DB,
		DialTimeout: cfg.Redis.DialTimeout, ReadTimeout: cfg.Redis.ReadTimeout, WriteTimeout: cfg.Redis.WriteTimeout,
		PoolSize: cfg.Redis.PoolSize, ClientName: "auth-service",
	}
	if cfg.Redis.TLS {
		// TODO TLS 12 чтобы проверка не ругалась
		redisOptions.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	redisClient := redis.NewClient(redisOptions)
	defer func() { _ = redisClient.Close() }()

	passwords, err := security.NewPasswordHasher(security.Argon2Params{
		Memory: cfg.Auth.ArgonMemoryKB, Iterations: cfg.Auth.ArgonTime, Parallelism: cfg.Auth.ArgonThreads,
		SaltLength: 16, KeyLength: cfg.Auth.ArgonKeyLength,
	})
	if err != nil {
		logger.Error("create password hasher", "error", err)
		os.Exit(1)
	}
	tokens, err := security.NewTokenManager(cfg.Auth.SessionHashKey)
	if err != nil {
		logger.Error("create token manager", "error", err)
		os.Exit(1)
	}

	metrics := httpapi.NewMetrics()
	userRepo := postgres.NewUserRepository(pool)
	sessionStore := redisstore.NewSessionStore(redisClient, cfg.Redis.KeyPrefix)
	rateLimiter := redisstore.NewRateLimiter(redisClient, cfg.Redis.KeyPrefix)
	rehashObserver := service.RehashObserverFunc(func(err error) {
		metrics.PasswordRehashFailed(err)
		logger.Warn("password rehash failed", "error", err)
	})
	authService, err := service.NewAuthService(userRepo, sessionStore, passwords, tokens, cfg.Auth.SessionTTL, cfg.Auth.PasswordMin, cfg.Auth.PasswordMax, cfg.Auth.HashConcurrency, rehashObserver)
	if err != nil {
		logger.Error("create auth service", "error", err)
		os.Exit(1)
	}

	clientIPs, err := httpapi.NewClientIPResolver(cfg.HTTP.TrustedProxyCIDRs)
	if err != nil {
		logger.Error("configure trusted proxies", "error", err)
		os.Exit(1)
	}
	dependencies := httpapi.NewDependencies(pool, redisClient, cfg.Postgres.HealthTimeout, cfg.Redis.HealthTimeout)
	api := httpapi.New(authService, rateLimiter, dependencies, logger, metrics, cfg.RateLimit, cfg.HTTP.MaxBodyBytes, cfg.HTTP.RequestTimeout, clientIPs)

	server := &http.Server{
		Addr: cfg.HTTP.Address, Handler: api.Router(),
		ErrorLog:    slog.NewLogLogger(logger.Handler(), slog.LevelError),
		ReadTimeout: cfg.HTTP.ReadTimeout, ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout, IdleTimeout: cfg.HTTP.IdleTimeout,
		MaxHeaderBytes: cfg.HTTP.MaxHeaderBytes,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("HTTP server started", "address", cfg.HTTP.Address, "environment", cfg.Environment)
		serverErrors <- server.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	var runErr error
	select {
	case signal := <-signals:
		logger.Info("shutdown signal received", "signal", signal.String())
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = err
			logger.Error("HTTP server stopped unexpectedly", "error", err)
		}
	}

	// TODO второй SIGTERM иногда ломает нормальную остановку
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		_ = server.Close()
	}
	logger.Info("service stopped")
	if runErr != nil {
		os.Exit(1)
	}
}
