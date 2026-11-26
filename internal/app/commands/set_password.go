package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/techorionai/constellation-platform-go/transaction"

	"github.com/techorionai/constellation-identity/internal/ports/passwordhasher"
	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// ErrPasswordSet means the user has a password already. The hosted page sets
// the first password only.
var ErrPasswordSet = errors.New("the user has a password already")

// SetPasswordDeps are the ports of the command that sets a first password.
type SetPasswordDeps struct {
	Users  users.Repository
	Hasher passwordhasher.Hasher
	Tx     transaction.Transactor
	// Events writes the audit entry and sends the notice. A nil value does neither.
	Events securityevents.Events
	Log    *slog.Logger
	// Now is the clock. The default is time.Now.
	Now Clock
}

// SetPasswordCommand sets the first password of a user that has none, for
// example a user who accepted an invite with an upstream account.
type SetPasswordCommand struct{ d SetPasswordDeps }

// NewSetPassword makes the command.
func NewSetPassword(d SetPasswordDeps) *SetPasswordCommand {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &SetPasswordCommand{d: d}
}

// SetPassword is the input of the command. The password is a secret.
type SetPassword struct {
	UserID   string
	Password string
	// Actor is the ID of the principal that sets the password. It is the user
	// for the hosted page.
	Actor string
}

// Execute checks the password rules, hashes the password, and stores the hash
// if the user has no password. A user with a password gives ErrPasswordSet.
func (c *SetPasswordCommand) Execute(ctx context.Context, in SetPassword) error {
	hash, err := preparePassword(ctx, c.d.Hasher, in.Password)
	if err != nil {
		return err
	}
	err = c.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		u, err := c.d.Users.LockByID(ctx, in.UserID)
		if err != nil {
			return err
		}
		if u.PasswordHash != "" {
			return ErrPasswordSet
		}
		return c.d.Users.SetPasswordHash(ctx, in.UserID, hash, c.d.Now().UTC())
	}, txName("set_password"))
	if errors.Is(err, ErrPasswordSet) {
		return err
	}
	if err != nil {
		return fmt.Errorf("set the password: %w", err)
	}
	c.d.Log.InfoContext(ctx, "identity.password.set", "event", "identity.password.set", "user_id", in.UserID)
	c.record(ctx, in)
	return nil
}

// record writes the audit entry and sends the notice of a new password. A
// first password is a new login method (VISION sections 7 and 11). A failure is
// logged and does not undo the change.
func (c *SetPasswordCommand) record(ctx context.Context, in SetPassword) {
	if c.d.Events == nil {
		return
	}
	actor := in.Actor
	if actor == "" {
		actor = in.UserID
	}
	at := c.d.Now().UTC().Truncate(time.Microsecond)
	if err := c.d.Events.RecordAudit(ctx, securityevents.AuditEntry{
		Action: securityevents.ActionPasswordSet, Actor: actor, TargetUserID: in.UserID, Result: securityevents.ResultSuccess, At: at,
	}); err != nil {
		c.d.Log.ErrorContext(ctx, "identity.audit.failed", "event", "identity.audit.failed", "action", securityevents.ActionPasswordSet, "error", err)
	}
	if err := c.d.Events.NotifyUser(ctx, securityevents.Notice{Kind: securityevents.NoticePasswordSet, TargetUserID: in.UserID, At: at}); err != nil {
		c.d.Log.ErrorContext(ctx, "identity.security_notice.failed", "event", "identity.security_notice.failed", "kind", securityevents.NoticePasswordSet, "error", err)
	}
}
