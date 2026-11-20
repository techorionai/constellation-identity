// Package sessions is the port of the browser sessions.
package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// ErrNotFound means the repository has no session with the key.
var ErrNotFound = errors.New("session not found")

// Repository stores the sessions. A call joins the transaction in the context.
type Repository interface {
	// Create adds a session.
	Create(ctx context.Context, s domain.Session) error
	// GetByTokenHash returns a session, or an error that wraps ErrNotFound.
	GetByTokenHash(ctx context.Context, hash string) (domain.Session, error)
	// Touch sets the last seen time and the idle expiry of a session that is
	// not revoked.
	Touch(ctx context.Context, id string, lastSeen, idleExpires time.Time) error
	// RevokeByTokenHash revokes a session. It does nothing for a session that
	// does not exist or is revoked already.
	RevokeByTokenHash(ctx context.Context, hash string, now time.Time) error
	// CountActive returns the number of sessions that are not revoked and have
	// not expired at the time now.
	CountActive(ctx context.Context, now time.Time) (int64, error)
}
