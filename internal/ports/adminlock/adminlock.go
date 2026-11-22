// Package adminlock is the port of the lock that makes the admin changes that
// can remove the last admin run one after the other.
package adminlock

import "context"

// Locker takes the lock of the admin changes.
type Locker interface {
	// Lock takes a transaction lock (pg_advisory_xact_lock). It holds until the
	// end of the transaction in the context. Call it in a transaction.
	Lock(ctx context.Context) error
}
