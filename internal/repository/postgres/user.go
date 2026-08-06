package postgres

import (
	"context"
	"errors"

	"github.com/acme/auth-service/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, email, passwordHash string) (domain.User, error) {
	var user domain.User
	err := r.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id, email, password_hash, created_at
	`, email, passwordHash).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		// TODO проверяю имя ограничения чтобы не поймать другую ошибку
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_email_key" {
			return domain.User{}, domain.ErrEmailAlreadyExists
		}
		return domain.User{}, repositoryError("create user", err)
	}
	return user, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (domain.User, error) {
	return r.find(ctx, `
		SELECT id, email, password_hash, created_at
		FROM users
		WHERE email = $1
	`, email)
}

func (r *UserRepository) FindByID(ctx context.Context, id int64) (domain.User, error) {
	return r.find(ctx, `
		SELECT id, email, password_hash, created_at
		FROM users
		WHERE id = $1
	`, id)
}

func (r *UserRepository) find(ctx context.Context, query string, arg any) (domain.User, error) {
	// один поиск использую для email и ID
	var user domain.User
	err := r.pool.QueryRow(ctx, query, arg).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrUserNotFound
	}
	if err != nil {
		return domain.User{}, repositoryError("find user", err)
	}
	return user, nil
}

func (r *UserRepository) UpdatePasswordHash(ctx context.Context, id int64, passwordHash string) error {
	result, err := r.pool.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, passwordHash, id)
	if err != nil {
		return repositoryError("update password hash", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}
