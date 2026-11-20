// Package postgres holds the PostgreSQL repositories.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	keyManagerLock  = "constellation:identity:key-manager"
	clientsSyncLock = "constellation:identity:clients-sync"
)

// ErrLockTimeout means that another session holds the advisory lock for longer
// than lockWait.
var ErrLockTimeout = errors.New("advisory lock wait timeout")

var (
	// lockWait is the longest time that a caller waits for the lock.
	lockWait = 2 * time.Minute
	// lockRetry is the time between two tries.
	lockRetry = 100 * time.Millisecond
)

func lockID(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64()) //nolint:gosec // The hash is only a lock key.
}

// withAdvisoryLock runs fn while a session advisory lock is held. The lock is
// on a dedicated connection, so the work of fn uses other connections. It
// tries the lock until lockWait ends, and then returns ErrLockTimeout. It
// releases the lock and the connection also when fn panics.
func withAdvisoryLock(ctx context.Context, pool *pgxpool.Pool, name string, fn func(ctx context.Context) error) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection for lock: %w", err)
	}
	id := lockID(name)
	deadline := time.NewTimer(lockWait)
	defer deadline.Stop()
	for {
		var got bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", id).Scan(&got); err != nil {
			conn.Release()
			return fmt.Errorf("take advisory lock: %w", err)
		}
		if got {
			break
		}
		select {
		case <-ctx.Done():
			conn.Release()
			return fmt.Errorf("take advisory lock: %w", ctx.Err())
		case <-deadline.C:
			conn.Release()
			return fmt.Errorf("take advisory lock %s: %w", name, ErrLockTimeout)
		case <-time.After(lockRetry):
		}
	}
	defer func() {
		// The unlock must work also when ctx has ended.
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", id); err != nil {
			// A connection with an unknown lock state must not return to the pool.
			conn.Conn().Close(unlockCtx) //nolint:errcheck,gosec // The pool drops the closed connection.
		}
		conn.Release()
	}()
	return fn(ctx)
}
