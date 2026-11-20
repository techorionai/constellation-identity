//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/techorionai/constellation-platform-go/resources/test/containers"
)

// The image is the same as PostgresImage in resources/test/testserver. That
// package imports this one through the composition root, so a test here
// cannot import it.
const postgresImage = "postgres:18.7-alpine"

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pg := containers.Postgres(t, containers.WithPostgresImage(postgresImage))
	url, _ := pg.NewDatabase(t)
	pool, err := pgxpool.New(context.Background(), string(url))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// R14: a waiter gives up after lockWait.
func TestR14_LockWaitHasALimit(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	oldWait, oldRetry := lockWait, lockRetry
	lockWait, lockRetry = 500*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { lockWait, lockRetry = oldWait, oldRetry })

	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- withAdvisoryLock(ctx, pool, "test-lock", func(context.Context) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	start := time.Now()
	err := withAdvisoryLock(ctx, pool, "test-lock", func(context.Context) error {
		t.Error("the second caller must not get the lock")
		return nil
	})
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("error = %v, want ErrLockTimeout", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("the waiter waited %s", time.Since(start))
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The lock is free again, and the waiter left no connection.
	if err := withAdvisoryLock(ctx, pool, "test-lock", func(context.Context) error { return nil }); err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if n := pool.Stat().AcquiredConns(); n != 0 {
		t.Fatalf("acquired connections = %d, want 0", n)
	}
}

// R14: a panic in fn releases the lock and the connection.
func TestR14_PanicReleasesLock(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	func() {
		defer func() { _ = recover() }()
		_ = withAdvisoryLock(ctx, pool, "test-lock", func(context.Context) error { panic("boom") })
	}()
	if n := pool.Stat().AcquiredConns(); n != 0 {
		t.Fatalf("acquired connections = %d, want 0", n)
	}
	oldWait := lockWait
	lockWait = time.Second
	t.Cleanup(func() { lockWait = oldWait })
	if err := withAdvisoryLock(ctx, pool, "test-lock", func(context.Context) error { return nil }); err != nil {
		t.Fatalf("lock after the panic: %v", err)
	}
}
