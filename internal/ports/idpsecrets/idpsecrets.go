// Package idpsecrets is the port of the client secrets of the upstream providers.
package idpsecrets

import (
	"context"
	"errors"
)

// ErrNotFound means the store has no secret for the provider.
var ErrNotFound = errors.New("client secret not found")

// Store keeps the client secrets in the secrets store.
type Store interface {
	// ClientSecret returns the secret. It wraps ErrNotFound if there is none.
	ClientSecret(ctx context.Context, provider string) (string, error)
	// PutClientSecret stores the secret.
	PutClientSecret(ctx context.Context, provider, secret string) error
}
