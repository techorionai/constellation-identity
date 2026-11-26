package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/techorionai/constellation-platform-go/transaction"

	"github.com/techorionai/constellation-identity/internal/ports/passwordhasher"
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
	return nil
}
