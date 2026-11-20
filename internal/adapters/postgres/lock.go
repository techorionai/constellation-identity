// Package postgres holds the PostgreSQL repositories.
package postgres

import (
	"context"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	keyManagerLock  = "constellation:identity:key-manager"
	clientsSyncLock = "constellation:identity:clients-sync"
)

func lockID(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64()) //nolint:gosec // The hash is only a lock key.
}

// withAdvisoryLock runs fn while a session advisory lock is held. The lock is
// on a dedicated connection, so the work of fn uses other connections.
func withAdvisoryLock(ctx context.Context, pool *pgxpool.Pool, name string, fn func(ctx context.Context) error) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection for lock: %w", err)
	}
	id := lockID(name)
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", id); err != nil {
		conn.Release()
		return fmt.Errorf("take advisory lock: %w", err)
	}
	runErr := fn(ctx)

	// The unlock must work also when ctx has ended.
	unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", id); err != nil {
		// A connection with an unknown lock state must not return to the pool.
		conn.Conn().Close(unlockCtx) //nolint:errcheck,gosec // The pool drops the closed connection.
	}
	conn.Release()
	return runErr
}
