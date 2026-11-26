// Package identitylinks is the port of the links between users and accounts at
// upstream identity providers.
package identitylinks

import (
	"context"
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Errors of the repository.
var (
	// ErrNotFound means the repository has no link with the key.
	ErrNotFound = errors.New("identity link not found")
	// ErrSubjectLinked means another link has the provider and the subject.
	ErrSubjectLinked = errors.New("the upstream account is linked to a user")
	// ErrProviderLinked means the user has a link for the provider.
	ErrProviderLinked = errors.New("the user has a link for the provider")
)

// Repository stores the links. A call joins the transaction in the context.
type Repository interface {
	// Create adds a link. It returns an error that wraps ErrSubjectLinked or
	// ErrProviderLinked for a duplicate.
	Create(ctx context.Context, l domain.IdentityLink) error
	// GetBySubject returns the link of an upstream account, or an error that
	// wraps ErrNotFound.
	GetBySubject(ctx context.Context, provider, subject string) (domain.IdentityLink, error)
	// GetByUserProvider returns the link of a user for a provider, or an error
	// that wraps ErrNotFound.
	GetByUserProvider(ctx context.Context, userID, provider string) (domain.IdentityLink, error)
	// ListByUser returns up to limit links of a user, in order of the creation
	// time and the provider, after the cursor. The ID of the cursor is the
	// provider. A nil cursor means the start.
	ListByUser(ctx context.Context, userID string, after *domain.PageCursor, limit int) ([]domain.IdentityLink, error)
	// Remove deletes the link of a user for a provider. It returns an error that
	// wraps ErrNotFound if there is none.
	Remove(ctx context.Context, userID, provider string) error
	// Touch sets the last use time and the email of a link.
	Touch(ctx context.Context, id, email string, now time.Time) error
	// CountUsersWithoutLoginMethod counts the active users that have no password,
	// no passkey that the service accepts, and no link of a provider that is on.
	CountUsersWithoutLoginMethod(ctx context.Context, providersOn []string, passkeysOn bool) (int, error)
}
