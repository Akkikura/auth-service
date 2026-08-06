package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed *.up.sql
var files embed.FS

// TODO номер блокировки должен быть одинаковым во всех версиях
const advisoryLockID int64 = 719341908247

type migrationFile struct {
	name    string
	version int64
}

func Up(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("migration database is required")
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version BIGINT PRIMARY KEY,
			checksum TEXT,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT;
	`); err != nil {
		return fmt.Errorf("prepare schema_migrations: %w", err)
	}

	for _, migration := range migrations {
		content, err := files.ReadFile(migration.name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", migration.name, err)
		}
		// хеш нужен чтобы старую миграцию не меняли
		sum := sha256.Sum256(content)
		checksum := hex.EncodeToString(sum[:])

		var stored sql.NullString
		err = tx.QueryRowContext(ctx, `SELECT checksum FROM schema_migrations WHERE version = $1`, migration.version).Scan(&stored)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(ctx, string(content)); err != nil {
				return fmt.Errorf("execute migration %s: %w", migration.name, err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`, migration.version, checksum); err != nil {
				return fmt.Errorf("record migration %s: %w", migration.name, err)
			}
		case err != nil:
			return fmt.Errorf("check migration %d: %w", migration.version, err)
		// TODO без хеша не могу проверить старую миграцию
		case !stored.Valid || stored.String == "":
			return fmt.Errorf("migration %s has no recorded checksum: manual schema reconciliation is required", migration.name)
		case stored.String != checksum:
			return fmt.Errorf("migration %s checksum mismatch: applied migration was modified", migration.name)
		}
	}

	if _, err := tx.ExecContext(ctx, `ALTER TABLE schema_migrations ALTER COLUMN checksum SET NOT NULL`); err != nil {
		return fmt.Errorf("enforce migration checksum: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

func loadMigrations() ([]migrationFile, error) {
	entries, err := fs.Glob(files, "*.up.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	result := make([]migrationFile, 0, len(entries))
	seen := make(map[int64]string, len(entries))
	for _, name := range entries {
		version, err := migrationVersion(name)
		if err != nil {
			return nil, err
		}
		if previous, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate migration version %d in %s and %s", version, previous, name)
		}
		seen[version] = name
		result = append(result, migrationFile{name: name, version: version})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].version < result[j].version })
	return result, nil
}

func migrationVersion(name string) (int64, error) {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok {
		prefix, _, ok = strings.Cut(name, ".")
	}
	if !ok {
		return 0, fmt.Errorf("invalid migration filename: %s", name)
	}
	version, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil || version <= 0 {
		return 0, fmt.Errorf("invalid migration version in %s", name)
	}
	return version, nil
}
