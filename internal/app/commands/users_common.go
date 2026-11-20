package commands

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/techorionai/constellation-platform-go/transaction"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/onetimetokens"
	"github.com/techorionai/constellation-identity/internal/ports/passwordhasher"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// Errors of the user use cases. A handler maps them to a page or a status.
var (
	// ErrTokenInvalid means a setup token or an invite token is unknown, used,
	// expired, or not usable for its user.
	ErrTokenInvalid = errors.New("the token is not valid")
	// ErrEmailTaken means another user has the email.
	ErrEmailTaken = errors.New("email_taken")
	// ErrUserNotFound means the user does not exist.
	ErrUserNotFound = errors.New("user_not_found")
	// ErrUserDisabled means the user is disabled.
	ErrUserDisabled = errors.New("user_disabled")
	// ErrUserNotInvited means the user is not in the status invited.
	ErrUserNotInvited = errors.New("user_not_invited")
	// ErrAdminExists means an active user has the role identity:admin.
	ErrAdminExists = errors.New("an active admin exists")
	// ErrBadCredentials means the email or the password is not correct, or the
	// user cannot log in. The cause is not visible to the caller.
	ErrBadCredentials = errors.New("email or password is not correct")
	// ErrTooManyAttempts means a login failure limit is reached.
	ErrTooManyAttempts = errors.New("too many attempts")
	// ErrLimiterUnavailable means the login failure counters are not available.
	// The login fails closed.
	ErrLimiterUnavailable = errors.New("the login limiter is not available")
	// ErrBusy means no password hash slot was free in time.
	ErrBusy = passwordhasher.ErrBusy
)

// Clock returns the current time.
type Clock func() time.Time

// Link is a one-time link. The URL holds the token value. It is a secret.
type Link struct {
	URL       string
	ExpiresAt time.Time
}

// IssuedSession is a new session. The token is the cookie value. It is a
// secret.
type IssuedSession struct {
	UserID    string
	Token     string
	ExpiresAt time.Time
}

// tokenLink makes a one-time link on the issuer.
func tokenLink(issuer, path, value string) string {
	return issuer + path + "?token=" + url.QueryEscape(value)
}

// newOneTimeToken makes the record and the value of a token.
func newOneTimeToken(purpose domain.TokenPurpose, userID string, now time.Time, ttl time.Duration) (domain.OneTimeToken, string, error) {
	value, hash, err := domain.NewSecret()
	if err != nil {
		return domain.OneTimeToken{}, "", err
	}
	return domain.OneTimeToken{
		Hash: hash, Purpose: purpose, UserID: userID, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}, value, nil
}

// sessionIssuer makes sessions in the repository of the context.
type sessionIssuer struct {
	repo   sessions.Repository
	policy domain.SessionPolicy
	now    Clock
}

// issue stores a new session for the user and returns the cookie value.
func (s sessionIssuer) issue(ctx context.Context, userID, userAgent, ip string) (IssuedSession, error) {
	value, hash, err := domain.NewSecret()
	if err != nil {
		return IssuedSession{}, err
	}
	id := newUUID()
	sess := s.policy.NewSession(userID, s.now().UTC())
	sess.ID, sess.TokenHash = id, hash
	sess.UserAgent, sess.IPAddress = clip(userAgent, 512), clip(ip, 64)
	if err := s.repo.Create(ctx, sess); err != nil {
		return IssuedSession{}, err
	}
	return IssuedSession{UserID: userID, Token: value, ExpiresAt: sess.ExpiresAt}, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// preparePassword normalizes a password, checks the policy, and hashes it.
func preparePassword(ctx context.Context, h passwordhasher.Hasher, password string) (string, error) {
	n := h.Normalize(password)
	if err := domain.CheckPassword(n); err != nil {
		return "", err
	}
	hash, err := h.Hash(ctx, n)
	if err != nil {
		return "", fmt.Errorf("hash the password: %w", err)
	}
	return hash, nil
}

// createUserErr maps the error of a user insert.
func createUserErr(err error) error {
	if errors.Is(err, users.ErrEmailTaken) {
		return ErrEmailTaken
	}
	return err
}

// useToken uses a token in the transaction of ctx. A token that cannot be used
// gives ErrTokenInvalid.
func useToken(ctx context.Context, repo onetimetokens.Repository, value string, purpose domain.TokenPurpose, now time.Time) (string, error) {
	if value == "" || len(value) > domain.MaxTokenValueLength {
		return "", ErrTokenInvalid
	}
	userID, ok, err := repo.Use(ctx, domain.HashSecret(value), purpose, now)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrTokenInvalid
	}
	return userID, nil
}

// txName gives the transaction a name for the traces.
func txName(name string) transaction.Option { return transaction.Name(name) }
