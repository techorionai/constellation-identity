// Package privatekeys is the port of the private key store. The store keeps
// the PEM text of a private key encrypted.
package privatekeys

import (
	"context"
	"errors"
)

// ErrNotFound means the store has no key with the name.
var ErrNotFound = errors.New("private key not found")

// ErrUndecryptable means the store has the key, but cannot decrypt it. The
// master key is not the one that encrypted it.
var ErrUndecryptable = errors.New("private key cannot be decrypted")

// Store keeps private keys by name.
type Store interface {
	Put(ctx context.Context, name string, pem []byte) error
	// Get returns the PEM text. It returns an error that wraps ErrNotFound
	// for an unknown name, and ErrUndecryptable when the master key is wrong.
	Get(ctx context.Context, name string) ([]byte, error)
	// Delete removes a key. Delete of an unknown name is not an error.
	Delete(ctx context.Context, name string) error
	// ListNames returns all names that start with prefix.
	ListNames(ctx context.Context, prefix string) ([]string, error)
}
