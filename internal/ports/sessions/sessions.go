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

// Reauth is the data of a same-user login that keeps the session.
type Reauth struct {
	// OldHash is the hash of the cookie value of the previous session.
	OldHash string
	// NewHash is the hash of the new cookie value.
	NewHash     string
	UserID      string
	Now         time.Time
	IdleExpires time.Time
	UserAgent   string
	IPAddress   string
	// Methods are the methods (amr) of the new login.
	Methods []string
}

// Repository stores the sessions. A call joins the transaction in the context.
type Repository interface {
	// Create adds a session.
	Create(ctx context.Context, s domain.Session) error
	// GetByTokenHash returns a session, or an error that wraps ErrNotFound.
	GetByTokenHash(ctx context.Context, hash string) (domain.Session, error)
	// GetByID returns a session, or an error that wraps ErrNotFound.
	GetByID(ctx context.Context, id string) (domain.Session, error)
	// ListByUser returns up to limit sessions of the user, in order of the
	// creation time and the ID, after the cursor. A nil cursor means the start.
	ListByUser(ctx context.Context, userID string, now time.Time, after *domain.PageCursor, limit int) ([]domain.Session, error)
	// Touch sets the last seen time and the idle expiry of a session that is
	// not revoked.
	Touch(ctx context.Context, id string, lastSeen, idleExpires time.Time) error
	// Reauthenticate is one UPDATE. It replaces the token hash and sets the
	// auth time of the session that has OldHash, the user, and that is valid at
	// the time Now. The ID, the creation time, and the absolute expiry do not
	// change. It returns the session ID and true, or false if no row changed.
	Reauthenticate(ctx context.Context, r Reauth) (sessionID string, ok bool, err error)
	// SetMethods replaces the methods (amr) of a session that is not revoked.
	SetMethods(ctx context.Context, id string, methods []string) error
	// DropSecondFactor removes the methods otp, rec, and mfa from the sessions
	// that are not revoked and from the refresh token families that are not
	// revoked, for the user.
	DropSecondFactor(ctx context.Context, userID string) error
	// RevokeByTokenHash revokes a session. It does nothing for a session that
	// does not exist or is revoked already.
	RevokeByTokenHash(ctx context.Context, hash string, now time.Time) error
	// RevokeCascade revokes the session and all refresh token families of the
	// session. It locks the session row first, then the family rows in
	// ascending ID order. It returns false if the session does not exist.
	RevokeCascade(ctx context.Context, id string, now time.Time) (found bool, err error)
	// RevokeAllOfUser revokes all sessions of the user and all their refresh
	// token families, in the lock order of RevokeCascade. It returns the number
	// of sessions that it revoked.
	RevokeAllOfUser(ctx context.Context, userID string, now time.Time) (int, error)
	// CountActive returns the number of sessions that are not revoked and have
	// not expired at the time now.
	CountActive(ctx context.Context, now time.Time) (int64, error)
}
