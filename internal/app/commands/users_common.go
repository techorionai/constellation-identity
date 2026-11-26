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
	// SessionID is the ID of the session. A login of the same user keeps it.
	SessionID string
	// AuthTime is the time of the last login of the session.
	AuthTime time.Time
	// AuthMethods are the methods of the last login (amr).
	AuthMethods []string
	// PendingToken is set when the login needs a second factor. The login made
	// no session then, and Token is empty. The value is the cookie value of the
	// pending login. It is a secret.
	PendingToken string
	// PendingExpiresAt is the end of the pending login.
	PendingExpiresAt time.Time
	// SetupRequired is true when the policy needs MFA for the user, the user has
	// no second factor, and the session is made. The handler sends the user to
	// the TOTP setup page.
	SetupRequired bool
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
func (s sessionIssuer) issue(ctx context.Context, userID, userAgent, ip string, methods []string) (IssuedSession, error) {
	value, hash, err := domain.NewSecret()
	if err != nil {
		return IssuedSession{}, err
	}
	id := newUUID()
	sess := s.policy.NewSession(userID, s.now().UTC(), methods)
	sess.ID, sess.TokenHash = id, hash
	sess.UserAgent, sess.IPAddress = clip(userAgent, 512), clip(ip, 64)
	if err := s.repo.Create(ctx, sess); err != nil {
		return IssuedSession{}, err
	}
	return IssuedSession{UserID: userID, Token: value, ExpiresAt: sess.ExpiresAt, SessionID: id, AuthTime: sess.AuthTime, AuthMethods: methods}, nil
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

// checkTokenValid reads a token before the password work. A token that is not
// valid gives ErrTokenInvalid, and no hash runs. The use of the token later is
// still one atomic statement.
func checkTokenValid(ctx context.Context, repo onetimetokens.Repository, value string, purpose domain.TokenPurpose, now time.Time) error {
	if value == "" || len(value) > domain.MaxTokenValueLength {
		return ErrTokenInvalid
	}
	ok, err := repo.IsValid(ctx, domain.HashSecret(value), purpose, now)
	if err != nil {
		return err
	}
	if !ok {
		return ErrTokenInvalid
	}
	return nil
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

// sessionStarter applies the re-login rule: a login of the same user keeps a
// valid previous session and gives it a new cookie value, a new auth time, and
// the new methods. In all other cases it revokes the previous session and makes
// a new one.
type sessionStarter struct {
	sessionIssuer
}

// start makes or keeps the session of a login.
func (s sessionStarter) start(ctx context.Context, userID, previousToken, userAgent, ip string, methods []string) (IssuedSession, error) {
	if kept, ok, err := s.reauthenticate(ctx, userID, previousToken, userAgent, ip, methods); err != nil {
		return IssuedSession{}, err
	} else if ok {
		return kept, nil
	}
	issued, err := s.issue(ctx, userID, userAgent, ip, methods)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("make the session: %w", err)
	}
	return issued, nil
}

// reauthenticate keeps the previous session if it is valid and belongs to the
// user. The cookie value always changes, and the old value stops in the same
// statement. If the statement changes no row (a parallel logout), or in any
// other case, it revokes the previous session and the caller makes a new one.
func (s sessionStarter) reauthenticate(ctx context.Context, userID, previousToken, userAgent, ip string, methods []string) (IssuedSession, bool, error) {
	if previousToken == "" {
		return IssuedSession{}, false, nil
	}
	now := s.now().UTC()
	oldHash := domain.HashSecret(previousToken)
	prev, err := s.repo.GetByTokenHash(ctx, oldHash)
	if err != nil && !errors.Is(err, sessions.ErrNotFound) {
		return IssuedSession{}, false, fmt.Errorf("get the previous session: %w", err)
	}
	if err == nil && prev.KeepOnRelogin(userID, now) {
		value, hash, err := domain.NewSecret()
		if err != nil {
			return IssuedSession{}, false, err
		}
		id, ok, err := s.repo.Reauthenticate(ctx, sessions.Reauth{
			OldHash: oldHash, NewHash: hash, UserID: userID, Now: now,
			IdleExpires: s.policy.IdleExpiry(prev, now),
			UserAgent:   clip(userAgent, 512), IPAddress: clip(ip, 64), Methods: methods,
		})
		if err != nil {
			return IssuedSession{}, false, fmt.Errorf("keep the session: %w", err)
		}
		if ok {
			return IssuedSession{UserID: userID, Token: value, ExpiresAt: prev.ExpiresAt, SessionID: id, AuthTime: now, AuthMethods: methods}, true, nil
		}
	}
	if err := s.repo.RevokeByTokenHash(ctx, oldHash, now); err != nil {
		return IssuedSession{}, false, fmt.Errorf("revoke the previous session: %w", err)
	}
	return IssuedSession{}, false, nil
}
