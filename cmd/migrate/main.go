package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"time"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/migrations"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "auth-service-migrate")
	postgresURL, err := config.LoadPostgresURL()
	if err != nil {
		logger.Error("load configuration", "error", err)
		os.Exit(1)
	}
	db, err := sql.Open("pgx", postgresURL)
	if err != nil {
		logger.Error("open PostgreSQL", "error", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()
	// TODO 10 секунд пока хватает для запуска миграций
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		logger.Error("connect PostgreSQL", "error", err)
		os.Exit(1)
	}
	if err := migrations.Up(ctx, db); err != nil {
		logger.Error("apply migrations", "error", err)
		os.Exit(1)
	}
	logger.Info("migrations applied")
}
