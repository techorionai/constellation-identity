// Package secretbox is the port that seals and opens the TOTP secret of a user.
package secretbox

import "errors"

// ErrCannotOpen means the sealed value does not open with the keys that the
// service has.
var ErrCannotOpen = errors.New("the sealed secret cannot be opened")

// Sealer seals a secret. The user ID binds the sealed value to one user, so
// that a value copied to the row of another user does not open.
type Sealer interface {
	// Seal returns the sealed value and the ID of the key that sealed it.
	Seal(userID string, plaintext []byte) (sealed []byte, keyID string, err error)
	// Open returns the secret. It wraps ErrCannotOpen for a value that does not open.
	Open(userID string, sealed []byte) ([]byte, error)
}
