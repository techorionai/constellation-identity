// Package users is the port of the user repository.
package users

import (
	"context"
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Errors of the repository.
var (
	// ErrNotFound means the repository has no user with the key.
	ErrNotFound = errors.New("user not found")
	// ErrEmailTaken means another user has the email.
	ErrEmailTaken = errors.New("email taken")
)

// Repository stores the users. A call joins the transaction in the context.
type Repository interface {
	// Create adds a user. It returns ErrEmailTaken for a duplicate email.
	Create(ctx context.Context, u domain.User) error
	// GetByID returns a user, or an error that wraps ErrNotFound.
	GetByID(ctx context.Context, id string) (domain.User, error)
	// GetByEmail returns a user by the normalized email, or an error that wraps
	// ErrNotFound.
	GetByEmail(ctx context.Context, email string) (domain.User, error)
	// LockByID returns a user and locks its row until the end of the
	// transaction (SELECT ... FOR UPDATE). Call it in a transaction.
	LockByID(ctx context.Context, id string) (domain.User, error)
	// Activate sets the password hash and the status active.
	Activate(ctx context.Context, id, passwordHash string, now time.Time) error
	// SetPasswordHash replaces the password hash. The status does not change.
	SetPasswordHash(ctx context.Context, id, passwordHash string, now time.Time) error
	// SetStatus sets the status of a user.
	SetStatus(ctx context.Context, id string, status domain.UserStatus, now time.Time) error
}
