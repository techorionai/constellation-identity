// Package passwordhasher is the port of the password hash.
package passwordhasher

import (
	"context"
	"errors"
)

// ErrBusy means no hash slot was free before the queue timeout.
var ErrBusy = errors.New("the password hasher is busy")

// Hasher normalizes, hashes, and verifies passwords.
type Hasher interface {
	// Normalize returns the password in NFC form.
	Normalize(password string) string
	// Hash returns the encoded hash of a normalized password.
	Hash(ctx context.Context, password string) (string, error)
	// Verify checks a normalized password against an encoded hash. needsRehash
	// is true if the hash uses old parameters.
	Verify(ctx context.Context, password, encoded string) (ok, needsRehash bool, err error)
}
