// Package passkeys is the port of the stored passkeys (WebAuthn credentials)
// and the WebAuthn user handles.
package passkeys

import (
	"context"
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Errors of the repository.
var (
	// ErrNotFound means the user has no passkey with the ID, or no credential has
	// the credential ID, or no user has the handle.
	ErrNotFound = errors.New("passkey not found")
	// ErrLimit means the user has the largest number of passkeys.
	ErrLimit = errors.New("passkey limit reached")
	// ErrCredentialExists means a passkey with the credential ID exists already.
	ErrCredentialExists = errors.New("credential exists already")
)

// Repository stores the passkeys. A call joins the transaction in the context.
type Repository interface {
	// List returns up to limit passkeys of the user in order of the creation time
	// and the ID (ascending), after the cursor. A nil cursor means the start.
	List(ctx context.Context, userID string, after *domain.PageCursor, limit int) ([]domain.Passkey, error)
	// Get returns the passkey of the user, or an error that wraps ErrNotFound.
	Get(ctx context.Context, userID, id string) (domain.Passkey, error)
	// Credentials returns all credentials of the user.
	Credentials(ctx context.Context, userID string) ([]domain.PasskeyCredential, error)
	// ByCredentialID returns the credential with the credential ID, or an error
	// that wraps ErrNotFound.
	ByCredentialID(ctx context.Context, credentialID []byte) (domain.PasskeyCredential, error)
	// Insert adds a credential. In one transaction it checks that the user has
	// fewer than max passkeys. It returns an error that wraps ErrLimit or
	// ErrCredentialExists.
	Insert(ctx context.Context, c domain.PasskeyCredential, max int) error
	// Rename sets the name of the passkey of the user. It returns the old name, or
	// an error that wraps ErrNotFound.
	Rename(ctx context.Context, userID, id, name string) (oldName string, err error)
	// Remove deletes the passkey of the user, or returns an error that wraps
	// ErrNotFound.
	Remove(ctx context.Context, userID, id string) error
	// RemoveAll deletes all passkeys of the user. It returns the number.
	RemoveAll(ctx context.Context, userID string) (int, error)
	// Count returns the number of passkeys of the user.
	Count(ctx context.Context, userID string) (int, error)
	// AdvanceSignCount is one statement. It stores the new count, the backup
	// state, and the time of the use if the sign count rule accepts the new
	// count against the stored count. It returns false if no row changed.
	AdvanceSignCount(ctx context.Context, id string, next uint32, backupState bool, now time.Time) (bool, error)
	// EnsureUserHandle returns the WebAuthn user handle of the user. If the user
	// has none, it stores candidate and returns it. A parallel call gets the
	// stored value.
	EnsureUserHandle(ctx context.Context, userID string, candidate []byte) ([]byte, error)
	// UserIDByHandle returns the ID of the user with the handle, or an error that
	// wraps ErrNotFound.
	UserIDByHandle(ctx context.Context, handle []byte) (string, error)
}
