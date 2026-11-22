// Package clients is the port of the client repository.
package clients

import (
	"context"
	"errors"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Errors of the repository.
var (
	// ErrNotFound means the repository has no client with the ID.
	ErrNotFound = errors.New("client not found")
	// ErrExists means a client with the ID exists.
	ErrExists = errors.New("client exists")
	// ErrKeyExists means the client has a key with the kid.
	ErrKeyExists = errors.New("key exists")
)

// Repository stores the OAuth clients and their public keys.
type Repository interface {
	// UpsertConfig adds or updates a client of the clients file, and replaces
	// its keys and redirect URIs. It does not change a client with source api.
	// It returns false in that case.
	UpsertConfig(ctx context.Context, c domain.ClientConfig) (applied bool, err error)
	// DisableConfigNotIn sets disabled on each client with source config whose
	// ID is not in ids. It returns the IDs that it changed.
	DisableConfigNotIn(ctx context.Context, ids []string) ([]string, error)
	// Get returns a client with its redirect URIs. It returns an error that
	// wraps ErrNotFound.
	Get(ctx context.Context, id string) (domain.Client, error)
	// Keys returns the public keys of a client.
	Keys(ctx context.Context, id string) ([]domain.ClientKey, error)
	// Create adds a client with source api, its redirect URIs, and an optional
	// key. A duplicate ID gives ErrExists.
	Create(ctx context.Context, c domain.Client, key *domain.ClientKey) error
	// Update writes the name, the disabled flag, and the redirect URIs of a
	// client. It returns an error that wraps ErrNotFound.
	Update(ctx context.Context, c domain.Client) error
	// LockByID returns a client and locks its row. Call it in a transaction.
	LockByID(ctx context.Context, id string) (domain.Client, error)
	// List returns up to limit clients in order of the creation time and the
	// ID, after the cursor. A nil cursor means the start.
	List(ctx context.Context, after *domain.PageCursor, limit int) ([]domain.Client, error)
	// AddKey adds a key. A duplicate kid gives ErrKeyExists.
	AddKey(ctx context.Context, k domain.ClientKey) error
	// DeleteKey removes a key. It returns false if the client has no such key.
	DeleteKey(ctx context.Context, clientID, kid string) (bool, error)
	// LoginRedirectURIs returns the login redirect URIs of all public clients
	// that are not disabled. It is the source of the CORS origins.
	LoginRedirectURIs(ctx context.Context) ([]string, error)
	// WithLock runs fn while this instance holds the cluster lock of the
	// clients sync.
	WithLock(ctx context.Context, fn func(ctx context.Context) error) error
}
