package database

import (
	"boring-machine/internal/database/sqlc"
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps the connection pool and queries
type DB struct {
	Pool    *pgxpool.Pool
	Queries *sqlc.Queries
}

// New creates a new database connection and returns a DB instance
func New(ctx context.Context, connString string) (*DB, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{
		Pool:    pool,
		Queries: sqlc.New(pool),
	}, nil
}

// Close closes the database connection pool
func (db *DB) Close() {
	db.Pool.Close()
}
