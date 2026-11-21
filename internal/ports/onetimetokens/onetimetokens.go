// Package onetimetokens is the port of the setup tokens and invite tokens.
package onetimetokens

import (
	"context"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Repository stores the one-time tokens. A call joins the transaction in the
// context.
type Repository interface {
	// Create adds a token.
	Create(ctx context.Context, t domain.OneTimeToken) error
	// Use marks an unused token with the hash and the purpose as used, if it
	// has not expired at the time now. It is one statement, so two parallel
	// calls cannot both succeed. It returns the user ID of the token (empty for
	// a setup token) and true on success.
	Use(ctx context.Context, hash string, purpose domain.TokenPurpose, now time.Time) (userID string, ok bool, err error)
	// IsValid reports whether an unused and unexpired token exists. It does not
	// change the token.
	IsValid(ctx context.Context, hash string, purpose domain.TokenPurpose, now time.Time) (bool, error)
	// FindValid reads an unused and unexpired token. It returns the user ID of
	// the token (empty for a setup token) and true if the token is valid. It
	// takes no lock and does not change the token.
	FindValid(ctx context.Context, hash string, purpose domain.TokenPurpose, now time.Time) (userID string, ok bool, err error)
	// HasValidSetup reports whether an unused and unexpired setup token exists.
	HasValidSetup(ctx context.Context, now time.Time) (bool, error)
	// DeleteUnusedSetup deletes each unused setup token.
	DeleteUnusedSetup(ctx context.Context) error
	// DeleteUnusedInvites deletes each unused invite token of a user.
	DeleteUnusedInvites(ctx context.Context, userID string) error
	// WithSetupLock runs fn while this instance holds the cluster lock of the
	// first-admin setup.
	WithSetupLock(ctx context.Context, fn func(ctx context.Context) error) error
}
