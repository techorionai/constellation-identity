// Package clients is the port of the client repository.
package clients

import (
	"context"
	"errors"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// ErrNotFound means the repository has no client with the ID.
var ErrNotFound = errors.New("client not found")

// Repository stores the OAuth clients and their public keys.
type Repository interface {
	// UpsertConfig adds or updates a client of the clients file, and replaces
	// its keys. It does not change a client with source api. It returns false
	// in that case.
	UpsertConfig(ctx context.Context, c domain.ClientConfig) (applied bool, err error)
	// DisableConfigNotIn sets disabled on each client with source config whose
	// ID is not in ids. It returns the IDs that it changed.
	DisableConfigNotIn(ctx context.Context, ids []string) ([]string, error)
	// Get returns a client. It returns an error that wraps ErrNotFound.
	Get(ctx context.Context, id string) (domain.Client, error)
	// Keys returns the public keys of a client.
	Keys(ctx context.Context, id string) ([]domain.ClientKey, error)
	// WithLock runs fn while this instance holds the cluster lock of the
	// clients sync.
	WithLock(ctx context.Context, fn func(ctx context.Context) error) error
}
