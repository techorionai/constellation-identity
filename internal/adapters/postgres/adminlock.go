package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/ports/adminlock"
)

// adminChangeLock is the name of the transaction lock of the admin changes.
const adminChangeLock = "constellation:identity:admin-change"

// AdminLock is the transaction lock of the admin changes. It differs from the
// session locks of the key manager and the clients sync.
type AdminLock struct {
	pool *pgxpool.Pool
}

var _ adminlock.Locker = (*AdminLock)(nil)

// NewAdminLock makes the lock.
func NewAdminLock(pool *pgxpool.Pool) *AdminLock { return &AdminLock{pool: pool} }

// Lock takes pg_advisory_xact_lock. It holds until the transaction ends.
func (l *AdminLock) Lock(ctx context.Context) error {
	if _, ok := clientspg.TxFromContext(ctx); !ok {
		return fmt.Errorf("take admin lock: no transaction in the context")
	}
	if _, err := clientspg.Conn(ctx, l.pool).Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID(adminChangeLock)); err != nil {
		return fmt.Errorf("take admin lock: %w", err)
	}
	return nil
}
