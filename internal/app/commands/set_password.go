package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/techorionai/constellation-platform-go/audit"
	"github.com/techorionai/constellation-platform-go/transaction"

	"github.com/techorionai/constellation-identity/internal/ports/passwordhasher"
	"github.com/techorionai/constellation-identity/internal/ports/securitynotices"
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
	// Events sends the notice. A nil value sends none. Audit writes the audit
	// entry in the transaction of the change.
	Events securitynotices.Notices
	Audit  audit.Writer
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
	// for the hosted page. The audit actor is the principal of the context.
	Actor string
	// Origin is OriginPasswordLink when a one-time link starts the flow. It is
	// empty when a session of the user starts it.
	Origin string
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
		if err := c.d.Users.SetPasswordHash(ctx, in.UserID, hash, c.d.Now().UTC()); err != nil {
			return err
		}
		return writeAudit(ctx, c.d.Audit, c.d.Now().UTC(), ActionPasswordSet, targetUser, in.UserID, originDetails(in.Origin, nil))
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

// record sends the notice of a new password. A first password is a new login
// method (VISION sections 7 and 11). A failure is logged and does not undo the
// change.
func (c *SetPasswordCommand) record(ctx context.Context, in SetPassword) {
	if c.d.Events == nil {
		return
	}
	at := c.d.Now().UTC().Truncate(time.Microsecond)
	if err := c.d.Events.NotifyUser(ctx, securitynotices.Notice{Kind: securitynotices.NoticePasswordSet, TargetUserID: in.UserID, At: at}); err != nil {
		c.d.Log.ErrorContext(ctx, "identity.security_notice.failed", "event", "identity.security_notice.failed", "kind", securitynotices.NoticePasswordSet, "error", err)
	}
}
