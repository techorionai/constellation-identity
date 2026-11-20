package commands

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/techorionai/constellation-platform-go/executor"
	"github.com/techorionai/constellation-platform-go/transaction"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/onetimetokens"
	"github.com/techorionai/constellation-identity/internal/ports/passwordhasher"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// InviteDeps are the ports of the invite commands.
type InviteDeps struct {
	Issuer  string
	TTL     time.Duration
	Tokens  onetimetokens.Repository
	Users   users.Repository
	Session sessions.Repository
	Hasher  passwordhasher.Hasher
	Tx      transaction.Transactor
	Policy  domain.SessionPolicy
	Log     *slog.Logger
	// Now is the clock. The default is time.Now.
	Now Clock
}

func (d *InviteDeps) defaults() {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
}

// CreateUser is the input of the user creation.
type CreateUser struct {
	Email string
	Name  string
}

// CreateUserResult is the new user and the invite.
type CreateUserResult struct {
	User   domain.User
	Invite Link
}

// CreateUserCommand makes an invited user and an invite.
type CreateUserCommand struct{ d InviteDeps }

var _ executor.ExecutorWithReturn[CreateUser, CreateUserResult] = (*CreateUserCommand)(nil)

// NewCreateUser makes the command.
func NewCreateUser(d InviteDeps) *CreateUserCommand {
	d.defaults()
	return &CreateUserCommand{d: d}
}

// Execute makes the user and the invite in one transaction.
func (c *CreateUserCommand) Execute(ctx context.Context, in CreateUser) (CreateUserResult, error) {
	email, err := domain.NormalizeEmail(in.Email)
	if err != nil {
		return CreateUserResult{}, err
	}
	name, err := domain.CheckName(in.Name)
	if err != nil {
		return CreateUserResult{}, err
	}
	var res CreateUserResult
	err = c.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		now := c.d.Now().UTC()
		res.User = domain.User{
			ID: newUUID(), Email: email, Name: name, Status: domain.UserInvited, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.d.Users.Create(ctx, res.User); err != nil {
			return createUserErr(err)
		}
		res.Invite, err = makeInvite(ctx, c.d, res.User.ID, now)
		return err
	}, txName("create_user"))
	if err != nil {
		return CreateUserResult{}, wrapUserErr("create the user", err)
	}
	c.d.Log.InfoContext(ctx, "identity.user.created", "event", "identity.user.created", "user_id", res.User.ID)
	return res, nil
}

func makeInvite(ctx context.Context, d InviteDeps, userID string, now time.Time) (Link, error) {
	rec, value, err := newOneTimeToken(domain.PurposeInvite, userID, now, d.TTL)
	if err != nil {
		return Link{}, err
	}
	if err := d.Tokens.Create(ctx, rec); err != nil {
		return Link{}, err
	}
	return Link{URL: tokenLink(d.Issuer, "/invite", value), ExpiresAt: rec.ExpiresAt}, nil
}

// CreateInvite is the input of the invite creation.
type CreateInvite struct {
	UserID string
}

// CreateInviteCommand makes an invite for a user with the status invited.
type CreateInviteCommand struct{ d InviteDeps }

var _ executor.ExecutorWithReturn[CreateInvite, Link] = (*CreateInviteCommand)(nil)

// NewCreateInvite makes the command.
func NewCreateInvite(d InviteDeps) *CreateInviteCommand {
	d.defaults()
	return &CreateInviteCommand{d: d}
}

// Execute locks the user, checks the status, deletes the older unused invites,
// and makes a new invite. A disabled user gives ErrUserDisabled. An active user
// gives ErrUserNotInvited.
func (c *CreateInviteCommand) Execute(ctx context.Context, in CreateInvite) (Link, error) {
	var link Link
	err := c.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		user, err := c.d.Users.LockByID(ctx, in.UserID)
		if errors.Is(err, users.ErrNotFound) {
			return ErrUserNotFound
		}
		if err != nil {
			return err
		}
		switch user.Status {
		case domain.UserDisabled:
			return ErrUserDisabled
		case domain.UserInvited:
		default:
			return ErrUserNotInvited
		}
		if err := c.d.Tokens.DeleteUnusedInvites(ctx, user.ID); err != nil {
			return err
		}
		link, err = makeInvite(ctx, c.d, user.ID, c.d.Now().UTC())
		return err
	}, txName("create_invite"))
	if err != nil {
		return Link{}, wrapUserErr("create the invite", err)
	}
	c.d.Log.InfoContext(ctx, "identity.invite.created", "event", "identity.invite.created", "user_id", in.UserID)
	return link, nil
}

// AcceptInvite is the input of the invite form. The password is a secret.
type AcceptInvite struct {
	Token     string
	Password  string
	UserAgent string
	IP        string
}

// AcceptInviteCommand sets the password of an invited user and makes a session.
type AcceptInviteCommand struct{ d InviteDeps }

var _ executor.ExecutorWithReturn[AcceptInvite, IssuedSession] = (*AcceptInviteCommand)(nil)

// NewAcceptInvite makes the command.
func NewAcceptInvite(d InviteDeps) *AcceptInviteCommand {
	d.defaults()
	return &AcceptInviteCommand{d: d}
}

// Execute checks the password and hashes it. Then, in one transaction, it uses
// the token, locks the user, checks that the user is invited, sets the hash and
// the status active, and makes a session. A user that is not invited gives
// ErrTokenInvalid and the transaction rolls back, so the token stays unused.
func (c *AcceptInviteCommand) Execute(ctx context.Context, in AcceptInvite) (IssuedSession, error) {
	hash, err := preparePassword(ctx, c.d.Hasher, in.Password)
	if err != nil {
		return IssuedSession{}, err
	}
	var issued IssuedSession
	err = c.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		now := c.d.Now().UTC()
		userID, err := useToken(ctx, c.d.Tokens, in.Token, domain.PurposeInvite, now)
		if err != nil {
			return err
		}
		user, err := c.d.Users.LockByID(ctx, userID)
		if errors.Is(err, users.ErrNotFound) {
			return ErrTokenInvalid
		}
		if err != nil {
			return err
		}
		if user.Status != domain.UserInvited {
			return ErrTokenInvalid
		}
		if err := c.d.Users.Activate(ctx, user.ID, hash, now); err != nil {
			return err
		}
		issued, err = sessionIssuer{repo: c.d.Session, policy: c.d.Policy, now: c.d.Now}.issue(ctx, user.ID, in.UserAgent, in.IP)
		return err
	}, txName("accept_invite"))
	if err != nil {
		return IssuedSession{}, wrapUserErr("accept the invite", err)
	}
	c.d.Log.InfoContext(ctx, "identity.invite.accepted", "event", "identity.invite.accepted", "user_id", issued.UserID)
	return issued, nil
}
