package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/techorionai/constellation-platform-go/executor"
	"github.com/techorionai/constellation-platform-go/transaction"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/onetimetokens"
	"github.com/techorionai/constellation-identity/internal/ports/passwordhasher"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/userroles"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// SetupDeps are the ports of the setup commands.
type SetupDeps struct {
	Issuer  string
	TTL     time.Duration
	Tokens  onetimetokens.Repository
	Roles   userroles.Repository
	Users   users.Repository
	Session sessions.Repository
	Hasher  passwordhasher.Hasher
	Tx      transaction.Transactor
	Policy  domain.SessionPolicy
	Log     *slog.Logger
	// Now is the clock. The default is time.Now.
	Now Clock
}

func (d *SetupDeps) defaults() {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
}

// EnsureSetupToken is the input of the startup step. It has no fields.
type EnsureSetupToken struct{}

// EnsureSetupTokenResult tells what the startup step did. Link is empty when
// no token was made.
type EnsureSetupTokenResult struct {
	Link Link
}

// EnsureSetupTokenCommand makes a setup token if the install has no admin and
// no valid setup token.
type EnsureSetupTokenCommand struct{ d SetupDeps }

var _ executor.ExecutorWithReturn[EnsureSetupToken, EnsureSetupTokenResult] = (*EnsureSetupTokenCommand)(nil)

// NewEnsureSetupToken makes the command.
func NewEnsureSetupToken(d SetupDeps) *EnsureSetupTokenCommand {
	d.defaults()
	return &EnsureSetupTokenCommand{d: d}
}

// Execute takes the setup lock, then checks for an active admin and for a valid
// setup token.
func (c *EnsureSetupTokenCommand) Execute(ctx context.Context, _ EnsureSetupToken) (EnsureSetupTokenResult, error) {
	var res EnsureSetupTokenResult
	err := c.d.Tokens.WithSetupLock(ctx, func(ctx context.Context) error {
		admin, err := c.d.Roles.ActiveUserHasRole(ctx, domain.AdminRole)
		if err != nil || admin {
			return err
		}
		now := c.d.Now().UTC()
		valid, err := c.d.Tokens.HasValidSetup(ctx, now)
		if err != nil || valid {
			return err
		}
		res.Link, err = makeSetupToken(ctx, c.d, now)
		return err
	})
	if err != nil {
		return EnsureSetupTokenResult{}, fmt.Errorf("ensure the setup token: %w", err)
	}
	return res, nil
}

func makeSetupToken(ctx context.Context, d SetupDeps, now time.Time) (Link, error) {
	rec, value, err := newOneTimeToken(domain.PurposeSetup, "", now, d.TTL)
	if err != nil {
		return Link{}, err
	}
	if err := d.Tokens.Create(ctx, rec); err != nil {
		return Link{}, err
	}
	return Link{URL: tokenLink(d.Issuer, "/setup", value), ExpiresAt: rec.ExpiresAt}, nil
}

// ReplaceSetupToken is the input of the setup-link subcommand.
type ReplaceSetupToken struct{}

// ReplaceSetupTokenCommand deletes the unused setup tokens and makes a new
// one. It fails with ErrAdminExists if an active admin exists.
type ReplaceSetupTokenCommand struct{ d SetupDeps }

var _ executor.ExecutorWithReturn[ReplaceSetupToken, Link] = (*ReplaceSetupTokenCommand)(nil)

// NewReplaceSetupToken makes the command.
func NewReplaceSetupToken(d SetupDeps) *ReplaceSetupTokenCommand {
	d.defaults()
	return &ReplaceSetupTokenCommand{d: d}
}

// Execute takes the setup lock and replaces the token.
func (c *ReplaceSetupTokenCommand) Execute(ctx context.Context, _ ReplaceSetupToken) (Link, error) {
	var link Link
	err := c.d.Tokens.WithSetupLock(ctx, func(ctx context.Context) error {
		admin, err := c.d.Roles.ActiveUserHasRole(ctx, domain.AdminRole)
		if err != nil {
			return err
		}
		if admin {
			return ErrAdminExists
		}
		return c.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
			if err := c.d.Tokens.DeleteUnusedSetup(ctx); err != nil {
				return err
			}
			link, err = makeSetupToken(ctx, c.d, c.d.Now().UTC())
			return err
		}, txName("replace_setup_token"))
	})
	if errors.Is(err, ErrAdminExists) {
		return Link{}, ErrAdminExists
	}
	if err != nil {
		return Link{}, fmt.Errorf("replace the setup token: %w", err)
	}
	return link, nil
}

// CompleteSetup is the input of the setup form. The password is a secret.
type CompleteSetup struct {
	Token     string
	Email     string
	Name      string
	Password  string
	UserAgent string
	IP        string
}

// CompleteSetupCommand makes the first admin and a session.
type CompleteSetupCommand struct{ d SetupDeps }

var _ executor.ExecutorWithReturn[CompleteSetup, IssuedSession] = (*CompleteSetupCommand)(nil)

// NewCompleteSetup makes the command.
func NewCompleteSetup(d SetupDeps) *CompleteSetupCommand {
	d.defaults()
	return &CompleteSetupCommand{d: d}
}

// Execute reads the token, checks the input, and hashes the password. Then, in
// one transaction, it uses the token, checks that no active admin exists, makes
// the admin, and makes the session. A token that is not valid gives
// ErrTokenInvalid before any hash runs. An existing admin gives ErrTokenInvalid
// and the transaction rolls back, so the token stays unused. A check error
// leaves the token unused.
func (c *CompleteSetupCommand) Execute(ctx context.Context, in CompleteSetup) (IssuedSession, error) {
	if err := checkTokenValid(ctx, c.d.Tokens, in.Token, domain.PurposeSetup, c.d.Now().UTC()); err != nil {
		return IssuedSession{}, wrapUserErr("complete the setup", err)
	}
	email, err := domain.NormalizeEmail(in.Email)
	if err != nil {
		return IssuedSession{}, err
	}
	name, err := domain.CheckName(in.Name)
	if err != nil {
		return IssuedSession{}, err
	}
	hash, err := preparePassword(ctx, c.d.Hasher, in.Password)
	if err != nil {
		return IssuedSession{}, err
	}
	var issued IssuedSession
	err = c.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		now := c.d.Now().UTC()
		if _, err := useToken(ctx, c.d.Tokens, in.Token, domain.PurposeSetup, now); err != nil {
			return err
		}
		admin, err := c.d.Roles.ActiveUserHasRole(ctx, domain.AdminRole)
		if err != nil {
			return err
		}
		if admin {
			return ErrTokenInvalid
		}
		user := domain.User{
			ID: newUUID(), Email: email, Name: name, Status: domain.UserActive,
			PasswordHash: hash, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.d.Users.Create(ctx, user); err != nil {
			return createUserErr(err)
		}
		if err := c.d.Roles.Assign(ctx, user.ID, domain.AdminRole, domain.AssignmentAPI); err != nil {
			return err
		}
		issued, err = sessionIssuer{repo: c.d.Session, policy: c.d.Policy, now: c.d.Now}.issue(ctx, user.ID, in.UserAgent, in.IP, domain.MethodsPassword())
		return err
	}, txName("complete_setup"))
	if err != nil {
		return IssuedSession{}, wrapUserErr("complete the setup", err)
	}
	c.d.Log.InfoContext(ctx, "identity.setup.completed", "event", "identity.setup.completed", "user_id", issued.UserID)
	return issued, nil
}

// wrapUserErr adds the step to an unexpected error. It keeps the errors that a
// handler maps to a page unchanged.
func wrapUserErr(step string, err error) error {
	switch {
	case errors.Is(err, ErrTokenInvalid), errors.Is(err, ErrEmailTaken), errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrUserDisabled), errors.Is(err, ErrUserNotInvited), errors.Is(err, ErrBusy):
		return err
	}
	return fmt.Errorf("%s: %w", step, err)
}
