// Package signingkeys is the port of the signing key repository.
package signingkeys

import (
	"context"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Repository stores the data of the signing keys. It holds no private key.
type Repository interface {
	// List returns all keys, the oldest first.
	List(ctx context.Context) ([]domain.SigningKey, error)
	// Insert adds a key.
	Insert(ctx context.Context, key domain.SigningKey) error
	// UpdateState sets the state of a key. retiredAt is set only for the
	// state retired.
	UpdateState(ctx context.Context, kid string, state domain.KeyState, retiredAt *time.Time) error
	// Delete removes a key row.
	Delete(ctx context.Context, kid string) error
	// WithLock runs fn while this instance holds the cluster lock of the key
	// manager. Only one instance runs fn at a time.
	WithLock(ctx context.Context, fn func(ctx context.Context) error) error
}
