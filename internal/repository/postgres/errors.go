package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/acme/auth-service/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
)

func repositoryError(operation string, err error) error {
	if postgresUnavailable(err) {
		return fmt.Errorf("%w: %s: %w", domain.ErrUnavailable, operation, err)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func postgresUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || pgconn.Timeout(err) {
		return true
	}

	var networkError net.Error
	if errors.As(err, &networkError) {
		return true
	}

	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) {
		return false
	}

	// эти ошибки считаю временными и возвращаю 503
	// на остальные ошибки возвращаю 500
	// TODO коды ошибок пока выписал из логов
	if strings.HasPrefix(pgError.Code, "08") || strings.HasPrefix(pgError.Code, "53") {
		return true
	}
	switch pgError.Code {
	case "57P01", "57P02", "57P03", "58030":
		return true
	default:
		return false
	}
}
