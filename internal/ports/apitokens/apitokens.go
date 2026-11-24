// Package apitokens is the port of the personal API tokens.
package apitokens

import (
	"context"
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// ErrNotFound means the repository has no token with the key.
var ErrNotFound = errors.New("api token not found")

// Repository stores the personal API tokens. A call joins the transaction in
// the context.
type Repository interface {
	// Insert adds a token with the hash of its value.
	Insert(ctx context.Context, hash string, t domain.APIToken) error
	// CountActive counts the tokens of a user that are not revoked and that do
	// not expire at now or earlier.
	CountActive(ctx context.Context, userID string, now time.Time) (int, error)
	// CountAll counts all rows of a user: active, expired, and revoked.
	CountAll(ctx context.Context, userID string) (int, error)
	// ListByUser returns up to limit tokens of a user, newest first, after the
	// cursor. A nil cursor means the start.
	ListByUser(ctx context.Context, userID string, after *domain.PageCursor, limit int) ([]domain.APIToken, error)
	// GetByHash returns the token with the hash and the status of its user, or
	// an error that wraps ErrNotFound.
	GetByHash(ctx context.Context, hash string) (domain.APITokenWithOwner, error)
	// Revoke sets revoked_at if it is null. An empty owner means any owner.
	// It returns false if no token has the ID (and the owner).
	Revoke(ctx context.Context, id, owner string, now time.Time) (bool, error)
	// RevokeAllOfUser revokes all active tokens of a user. It returns the number
	// of tokens that it revoked.
	RevokeAllOfUser(ctx context.Context, userID string, now time.Time) (int, error)
	// TouchLastUsed sets last_used_at to now if it is null or older than
	// interval.
	TouchLastUsed(ctx context.Context, id string, now time.Time, interval time.Duration) error
}
