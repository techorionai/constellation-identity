// Package idpflow is the port of the short-lived records of the upstream flows.
package idpflow

import (
	"context"
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// ErrNotFound means the store has no record with the key.
var ErrNotFound = errors.New("flow not found")

// Store keeps the flow records. The key is the hash of the state.
type Store interface {
	// Put stores the record for the time ttl.
	Put(ctx context.Context, hash string, f domain.IdpFlow, ttl time.Duration) error
	// Take reads and deletes the record in one step. It wraps ErrNotFound.
	Take(ctx context.Context, hash string) (domain.IdpFlow, error)
}
