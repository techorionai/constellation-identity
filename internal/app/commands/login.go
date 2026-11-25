package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/techorionai/constellation-platform-go/executor"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/loginlimiter"
	"github.com/techorionai/constellation-identity/internal/ports/passwordhasher"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// dummyPassword is the password that the login hashes for an email that has no
// user, so that the response time is about the same.
const dummyPassword = "constellation dummy password for timing"

// Values of the attribute outcome of the metric identity.logins.
const (
	OutcomeOK             = "ok"
	OutcomeBadCredentials = "bad_credentials"
	OutcomeDisabled       = "disabled"
	OutcomeLimited        = "limited"
	OutcomeBusy           = "busy"
)

// LoginLimits are the failure limits of the login.
type LoginLimits struct {
	MaxFailuresPerEmail int64
	MaxFailuresPerIP    int64
}

// LoginDeps are the ports of the login commands.
type LoginDeps struct {
	Users   users.Repository
	Session sessions.Repository
	Hasher  passwordhasher.Hasher
	Limiter loginlimiter.Limiter
	Limits  LoginLimits
	Policy  domain.SessionPolicy
	Log     *slog.Logger
	// Now is the clock. The default is time.Now.
	Now Clock
}

func (d *LoginDeps) defaults() {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
}

// Login is the input of the login form. The password is a secret.
type Login struct {
	Email    string
	Password string
	// IP is the client IP address.
	IP string
	// IPKey is the key of the client for the login counter. The handler makes it
	// from the IP with the /64 rule for IPv6. If it is empty, the counter uses IP.
	IPKey string
	// IPCoarseKey is the coarse key of the client network (the IPv6 /48 prefix).
	// It is empty for an IPv4 address. The coarse counter has a limit that is
	// CoarseFactor times MaxFailuresPerIP, and it counts all attempts.
	IPCoarseKey string
	UserAgent   string
	// PreviousToken is the session cookie value of the request. A login of the
	// same user keeps a valid previous session and gives it a new cookie value
	// and a new auth time. In all other cases the login revokes that session
	// and makes a new one.
	PreviousToken string
}

// LoginCommand checks the credentials and makes a session.
type LoginCommand struct {
	d      LoginDeps
	logins metric.Int64Counter
}

var _ executor.ExecutorWithReturn[Login, IssuedSession] = (*LoginCommand)(nil)

// NewLogin makes the command.
func NewLogin(d LoginDeps) (*LoginCommand, error) {
	d.defaults()
	logins, err := otel.Meter("identity").Int64Counter("identity.logins",
		metric.WithDescription("Login attempts by outcome."))
	if err != nil {
		return nil, fmt.Errorf("make the login counter: %w", err)
	}
	return &LoginCommand{d: d, logins: logins}, nil
}

func (c *LoginCommand) count(ctx context.Context, outcome string) {
	c.logins.Add(context.WithoutCancel(ctx), 1, metric.WithAttributes(attribute.String("outcome", outcome)))
}

// Execute reserves an attempt in the failure counters, then checks the password. Every failure
// that the user can cause gives ErrBadCredentials, ErrTooManyAttempts, or
// ErrBusy. A limiter error gives ErrLimiterUnavailable and no hash runs.
func (c *LoginCommand) Execute(ctx context.Context, in Login) (IssuedSession, error) {
	email, err := domain.NormalizeEmail(in.Email)
	if err != nil {
		// The value cannot be an email of a user. It is still counted.
		email = normalizeLoose(in.Email)
	}
	// Reserve the attempt before the hash. The counters change in one atomic
	// step, so parallel requests cannot all pass the limit.
	emailAttempts, ipAttempts, err := c.d.Limiter.Reserve(ctx, email, in.counterKey())
	if err != nil {
		c.d.Log.ErrorContext(ctx, "identity.login.limiter_unavailable", "event", "identity.login.limiter_unavailable", "error", err)
		return IssuedSession{}, ErrLimiterUnavailable
	}
	var coarseAttempts int64
	if in.IPCoarseKey != "" {
		coarseAttempts, err = c.d.Limiter.ReserveCoarse(ctx, in.IPCoarseKey)
		if err != nil {
			c.d.Log.ErrorContext(ctx, "identity.login.limiter_unavailable", "event", "identity.login.limiter_unavailable", "error", err)
			return IssuedSession{}, ErrLimiterUnavailable
		}
	}
	if emailAttempts > c.d.Limits.MaxFailuresPerEmail || ipAttempts > c.d.Limits.MaxFailuresPerIP ||
		coarseAttempts > c.d.Limits.MaxFailuresPerIP*CoarseFactor {
		c.count(ctx, OutcomeLimited)
		c.d.Log.InfoContext(ctx, "identity.login.limited", "event", "identity.login.limited")
		return IssuedSession{}, ErrTooManyAttempts
	}

	user, found, err := c.findUser(ctx, email)
	if err != nil {
		return IssuedSession{}, err
	}
	password := c.d.Hasher.Normalize(in.Password)
	ok, needsRehash, err := c.checkPassword(ctx, password, user, found)
	if errors.Is(err, passwordhasher.ErrBusy) {
		c.count(ctx, OutcomeBusy)
		return IssuedSession{}, ErrBusy
	}
	if err != nil {
		return IssuedSession{}, fmt.Errorf("check the password: %w", err)
	}
	if !ok || !found || user.Status != domain.UserActive {
		outcome := OutcomeBadCredentials
		if found && user.Status == domain.UserDisabled {
			outcome = OutcomeDisabled
		}
		c.fail(ctx, outcome)
		return IssuedSession{}, ErrBadCredentials
	}

	if needsRehash {
		c.rehash(ctx, user.ID, password)
	}
	if err := c.d.Limiter.RecordSuccess(ctx, email, in.counterKey()); err != nil {
		c.d.Log.WarnContext(ctx, "identity.login.reset_failed", "event", "identity.login.reset_failed", "error", err)
	}
	if kept, ok, err := c.reauthenticate(ctx, user.ID, in); err != nil {
		return IssuedSession{}, err
	} else if ok {
		c.count(ctx, OutcomeOK)
		c.d.Log.InfoContext(ctx, "identity.login.ok", "event", "identity.login.ok", "user_id", user.ID)
		return kept, nil
	}
	issued, err := sessionIssuer{repo: c.d.Session, policy: c.d.Policy, now: c.d.Now}.issue(ctx, user.ID, in.UserAgent, in.IP)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("make the session: %w", err)
	}
	c.count(ctx, OutcomeOK)
	c.d.Log.InfoContext(ctx, "identity.login.ok", "event", "identity.login.ok", "user_id", user.ID)
	return issued, nil
}

// reauthenticate applies the re-login rule. The previous session is kept if it
// is valid and belongs to the user. The cookie value always changes, and the
// old value stops in the same statement. If the statement changes no row (a
// parallel logout), or in any other case, the command revokes the previous
// session and the caller makes a new one.
func (c *LoginCommand) reauthenticate(ctx context.Context, userID string, in Login) (IssuedSession, bool, error) {
	if in.PreviousToken == "" {
		return IssuedSession{}, false, nil
	}
	now := c.d.Now().UTC()
	oldHash := domain.HashSecret(in.PreviousToken)
	prev, err := c.d.Session.GetByTokenHash(ctx, oldHash)
	if err != nil && !errors.Is(err, sessions.ErrNotFound) {
		return IssuedSession{}, false, fmt.Errorf("get the previous session: %w", err)
	}
	if err == nil && prev.KeepOnRelogin(userID, now) {
		value, hash, err := domain.NewSecret()
		if err != nil {
			return IssuedSession{}, false, err
		}
		id, ok, err := c.d.Session.Reauthenticate(ctx, sessions.Reauth{
			OldHash: oldHash, NewHash: hash, UserID: userID, Now: now,
			IdleExpires: c.d.Policy.IdleExpiry(prev, now),
			UserAgent:   clip(in.UserAgent, 512), IPAddress: clip(in.IP, 64),
		})
		if err != nil {
			return IssuedSession{}, false, fmt.Errorf("keep the session: %w", err)
		}
		if ok {
			return IssuedSession{UserID: userID, Token: value, ExpiresAt: prev.ExpiresAt, SessionID: id, AuthTime: now}, true, nil
		}
	}
	if err := c.d.Session.RevokeByTokenHash(ctx, oldHash, now); err != nil {
		return IssuedSession{}, false, fmt.Errorf("revoke the previous session: %w", err)
	}
	return IssuedSession{}, false, nil
}

// normalizeLoose is the key of the failure counter for a value that is not an
// email.
func normalizeLoose(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

func (c *LoginCommand) findUser(ctx context.Context, email string) (domain.User, bool, error) {
	u, err := c.d.Users.GetByEmail(ctx, email)
	if errors.Is(err, users.ErrNotFound) {
		return domain.User{}, false, nil
	}
	if err != nil {
		return domain.User{}, false, fmt.Errorf("find the user: %w", err)
	}
	return u, true, nil
}

// checkPassword runs exactly one hash. A user with a hash is verified. In every
// other case the command hashes a constant dummy password.
func (c *LoginCommand) checkPassword(ctx context.Context, password string, u domain.User, found bool) (ok, needsRehash bool, err error) {
	if found && u.PasswordHash != "" {
		return c.d.Hasher.Verify(ctx, password, u.PasswordHash)
	}
	_, err = c.d.Hasher.Hash(ctx, dummyPassword)
	return false, false, err
}

func (c *LoginCommand) fail(ctx context.Context, outcome string) {
	c.count(ctx, outcome)
	c.d.Log.InfoContext(ctx, "identity.login.failed", "event", "identity.login.failed", "outcome", outcome)
}

// rehash replaces a hash that has old parameters. A failure is logged and does
// not stop the login.
func (c *LoginCommand) rehash(ctx context.Context, userID, password string) {
	hash, err := c.d.Hasher.Hash(ctx, password)
	if err == nil {
		err = c.d.Users.SetPasswordHash(ctx, userID, hash, c.d.Now().UTC())
	}
	if err != nil {
		c.d.Log.WarnContext(ctx, "identity.login.rehash_failed", "event", "identity.login.rehash_failed", "user_id", userID, "error", err)
	}
}

// Logout is the input of the logout.
type Logout struct {
	// Token is the session cookie value.
	Token string
	// UserID is for the log record. It can be empty.
	UserID string
}

// LogoutCommand revokes a session.
type LogoutCommand struct{ d LoginDeps }

var _ executor.Executor[Logout] = (*LogoutCommand)(nil)

// NewLogout makes the command.
func NewLogout(d LoginDeps) *LogoutCommand {
	d.defaults()
	return &LogoutCommand{d: d}
}

// Execute revokes the session. A token that matches no session is not an error.
func (c *LogoutCommand) Execute(ctx context.Context, in Logout) error {
	if in.Token == "" {
		return nil
	}
	if err := c.d.Session.RevokeByTokenHash(ctx, domain.HashSecret(in.Token), c.d.Now().UTC()); err != nil {
		return fmt.Errorf("revoke the session: %w", err)
	}
	c.d.Log.InfoContext(ctx, "identity.logout", "event", "identity.logout", "user_id", in.UserID)
	return nil
}

// TouchSession is the input of the session touch.
type TouchSession struct {
	Session domain.Session
}

// TouchSessionCommand updates the last seen time and the idle expiry of a
// session, at most one time a minute.
type TouchSessionCommand struct{ d LoginDeps }

var _ executor.Executor[TouchSession] = (*TouchSessionCommand)(nil)

// NewTouchSession makes the command.
func NewTouchSession(d LoginDeps) *TouchSessionCommand {
	d.defaults()
	return &TouchSessionCommand{d: d}
}

// Execute writes only if the last seen time is a minute old or more.
func (c *TouchSessionCommand) Execute(ctx context.Context, in TouchSession) error {
	now := c.d.Now().UTC()
	if !in.Session.NeedsTouch(now) {
		return nil
	}
	if err := c.d.Session.Touch(ctx, in.Session.ID, now, c.d.Policy.IdleExpiry(in.Session, now)); err != nil {
		return fmt.Errorf("touch the session: %w", err)
	}
	return nil
}

// counterKey returns the key of the IP counter of the login.
func (in Login) counterKey() string {
	if in.IPKey != "" {
		return in.IPKey
	}
	return in.IP
}
