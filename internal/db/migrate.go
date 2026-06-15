package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/jackc/pgx/v5"
)

func (s *Store) RunMigrations(ctx context.Context, dir string) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('pwdb-schema-migrations'))`); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('pwdb-schema-migrations'))`)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name TEXT PRIMARY KEY,
			checksum TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) == ".sql" {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(files)

	for _, file := range files {
		migrationSQL, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file, err)
		}
		name := filepath.Base(file)
		checksum := migrationChecksum(migrationSQL)

		var appliedChecksum string
		err = conn.QueryRow(ctx,
			`SELECT checksum FROM schema_migrations WHERE name = $1`,
			name,
		).Scan(&appliedChecksum)
		switch {
		case err == nil:
			if appliedChecksum != checksum {
				return fmt.Errorf("migration %s checksum mismatch", name)
			}
			continue
		case err != pgx.ErrNoRows:
			return fmt.Errorf("check migration %s: %w", name, err)
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		if err := applyMigration(ctx, tx, name, checksum, migrationSQL); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, tx pgx.Tx, name string, checksum string, migrationSQL []byte) error {
	if _, err := tx.Exec(ctx, string(migrationSQL)); err != nil {
		return fmt.Errorf("exec migration %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)`,
		name,
		checksum,
	); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	return nil
}

func migrationChecksum(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}
