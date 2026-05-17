// Package fleetdb provides the PostgreSQL data layer for pancake-fleet-server.
//
// Connection pooling uses pgxpool. Migrations are embedded via golang-migrate's
// iofs source so the binary is self-contained.
package fleetdb

import (
	"context"
	"embed"
	"fmt"
	"net/http"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"

	// stdlib driver for golang-migrate
	_ "github.com/jackc/pgx/v5/stdlib"
	"database/sql"
)

// migrationsFS is embedded at build time from fleet-server/migrations.
// The build script wires the //go:embed directive in a separate file
// (migrations_embed.go) because go:embed can only see siblings of the
// .go file with the directive. See fleet-server/migrations_embed.go.

// DB wraps a pgxpool.Pool with fleet-specific helpers.
type DB struct {
	*pgxpool.Pool
}

// Open creates a connection pool and verifies the database is reachable.
// dsn is a Postgres connection string (e.g. "postgres://u:p@host/db?sslmode=disable").
func Open(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Migrate applies all up-migrations from the embedded migrations FS.
// Idempotent: re-runs are no-ops once schema is at the latest version.
func Migrate(dsn string, migrationsFS embed.FS, subdir string) error {
	d, err := iofs.New(migrationsFS, subdir)
	if err != nil {
		return fmt.Errorf("iofs source: %w", err)
	}

	// golang-migrate needs *sql.DB, not pgxpool. Open a separate
	// connection for migrations.
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open migration db: %w", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("migrate driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", d, "pgx", driver)
	if err != nil {
		return fmt.Errorf("migrate.New: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// asJSON marshals v to a JSON string suitable for a JSONB column.
// Returns "{}" on empty input.
func asJSON(v string) string {
	if v == "" {
		return "{}"
	}
	return v
}

// Unused import suppression for net/http to keep godoc references stable.
var _ = http.StatusOK
