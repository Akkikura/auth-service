package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/acme/auth-service/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRepositoryErrorClassification(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		unavailable bool
	}{
		{name: "deadline", err: context.DeadlineExceeded, unavailable: true},
		{name: "connection exception", err: &pgconn.PgError{Code: "08006"}, unavailable: true},
		{name: "server starting", err: &pgconn.PgError{Code: "57P03"}, unavailable: true},
		{name: "undefined table", err: &pgconn.PgError{Code: "42P01"}, unavailable: false},
		{name: "invalid data", err: errors.New("scan conversion failed"), unavailable: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := repositoryError("operation", test.err)
			if got := errors.Is(err, domain.ErrUnavailable); got != test.unavailable {
				t.Fatalf("unavailable = %v, want %v: %v", got, test.unavailable, err)
			}
		})
	}
}
