package queries

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/techorionai/constellation-platform-go/executor"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/onetimetokens"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// ErrNoSession means the cookie gives no valid session.
var ErrNoSession = errors.New("no valid session")

// SessionFromCookie is the input of the session query.
type SessionFromCookie struct {
	// Token is the value of the session cookie.
	Token string
}

// SessionResult is a valid session and its user.
type SessionResult struct {
	Session domain.Session
	User    domain.User
}

// SessionFromCookieQuery reads the session and its user. It does not write.
type SessionFromCookieQuery struct {
	sessions sessions.Repository
	users    users.Repository
	now      func() time.Time
}

var _ executor.ExecutorWithReturn[SessionFromCookie, SessionResult] = (*SessionFromCookieQuery)(nil)

// NewSessionFromCookie makes the query. now is the clock. Nil means time.Now.
func NewSessionFromCookie(s sessions.Repository, u users.Repository, now func() time.Time) *SessionFromCookieQuery {
	if now == nil {
		now = time.Now
	}
	return &SessionFromCookieQuery{sessions: s, users: u, now: now}
}

// Execute returns the session and the user. It returns ErrNoSession for a
// session that is unknown, revoked, or expired, and for a user that is not
// active.
func (q *SessionFromCookieQuery) Execute(ctx context.Context, in SessionFromCookie) (SessionResult, error) {
	if in.Token == "" || len(in.Token) > domain.MaxTokenValueLength {
		return SessionResult{}, ErrNoSession
	}
	s, err := q.sessions.GetByTokenHash(ctx, domain.HashSecret(in.Token))
	if errors.Is(err, sessions.ErrNotFound) {
		return SessionResult{}, ErrNoSession
	}
	if err != nil {
		return SessionResult{}, fmt.Errorf("get the session: %w", err)
	}
	if !s.Valid(q.now().UTC()) {
		return SessionResult{}, ErrNoSession
	}
	u, err := q.users.GetByID(ctx, s.UserID)
	if errors.Is(err, users.ErrNotFound) {
		return SessionResult{}, ErrNoSession
	}
	if err != nil {
		return SessionResult{}, fmt.Errorf("get the session user: %w", err)
	}
	if u.Status != domain.UserActive {
		return SessionResult{}, ErrNoSession
	}
	return SessionResult{Session: s, User: u}, nil
}

// CheckOneTimeToken is the input of the token check.
type CheckOneTimeToken struct {
	Token   string
	Purpose domain.TokenPurpose
}

// CheckOneTimeTokenQuery tells if a token can still be used. It does not use
// the token.
type CheckOneTimeTokenQuery struct {
	tokens onetimetokens.Repository
	now    func() time.Time
}

var _ executor.ExecutorWithReturn[CheckOneTimeToken, bool] = (*CheckOneTimeTokenQuery)(nil)

// NewCheckOneTimeToken makes the query. now is the clock. Nil means time.Now.
func NewCheckOneTimeToken(t onetimetokens.Repository, now func() time.Time) *CheckOneTimeTokenQuery {
	if now == nil {
		now = time.Now
	}
	return &CheckOneTimeTokenQuery{tokens: t, now: now}
}

// Execute returns true if the token is unused and has not expired.
func (q *CheckOneTimeTokenQuery) Execute(ctx context.Context, in CheckOneTimeToken) (bool, error) {
	if in.Token == "" || len(in.Token) > domain.MaxTokenValueLength {
		return false, nil
	}
	ok, err := q.tokens.IsValid(ctx, domain.HashSecret(in.Token), in.Purpose, q.now().UTC())
	if err != nil {
		return false, fmt.Errorf("check the token: %w", err)
	}
	return ok, nil
}
