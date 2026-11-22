// Package refreshtokens is the port of the refresh token families and tokens.
package refreshtokens

import (
	"context"
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// ErrNotFound means the repository has no such family or token.
var ErrNotFound = errors.New("refresh token not found")

// Repository stores the families and the tokens. A call joins the transaction
// in the context. The lock order of all callers is the session row, then the
// family rows in ascending ID order.
type Repository interface {
	// InsertFamilyIfSessionValid adds the family and its first token in one
	// statement that checks the session. It inserts no row if the session is
	// revoked or expired at the time now. It returns true if it inserted.
	InsertFamilyIfSessionValid(ctx context.Context, f domain.RefreshFamily, t domain.RefreshToken, now time.Time) (bool, error)
	// LockSessionOfToken locks the session row of the family of the token. It
	// returns false if no such token exists.
	LockSessionOfToken(ctx context.Context, tokenHash string) (sessionID string, ok bool, err error)
	// LockFamilyOfToken locks the family row of the token. It returns false
	// if no such token exists.
	LockFamilyOfToken(ctx context.Context, tokenHash string) (domain.RefreshFamily, bool, error)
	// GetToken returns a token, or an error that wraps ErrNotFound.
	GetToken(ctx context.Context, tokenHash string) (domain.RefreshToken, error)
	// MarkUsed sets used_at of a token that is not used and has not expired. It
	// returns false if no row changed.
	MarkUsed(ctx context.Context, tokenHash string, now time.Time) (bool, error)
	// InsertToken adds a token.
	InsertToken(ctx context.Context, t domain.RefreshToken) error
	// RevokeFamily sets revoked_at of the family if it is not revoked.
	RevokeFamily(ctx context.Context, familyID string, now time.Time) error
	// RevokeSessionFamilies locks the families of the session in ascending ID
	// order and revokes them.
	RevokeSessionFamilies(ctx context.Context, sessionID string, now time.Time) error
	// RevokeClientFamilies locks the families of the client in ascending ID
	// order and revokes them.
	RevokeClientFamilies(ctx context.Context, clientID string, now time.Time) error
	// RefreshState reads, for one family, the data that the checks of a refresh
	// need: the client, the user, and the session.
	RefreshState(ctx context.Context, familyID string) (State, error)
}

// State is the data of a refresh check. It is read inside the lock.
type State struct {
	ClientDisabled bool
	UserActive     bool
	Session        domain.Session
}
