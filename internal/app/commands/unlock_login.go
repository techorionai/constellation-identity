package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/techorionai/constellation-platform-go/audit"
	"github.com/techorionai/constellation-platform-go/executor"
	"github.com/techorionai/constellation-platform-go/transaction"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/loginlimiter"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// UnlockLogin is the input of the removal of the login lock of one email.
type UnlockLogin struct {
	Email string
}

// UnlockLoginCommand deletes the failure counter of an email. The result is
// true if a counter existed. It does not change the counters of the IPs.
type UnlockLoginCommand struct {
	limiter loginlimiter.Limiter
	log     *slog.Logger
	users   users.Repository
	tx      transaction.Transactor
	audit   audit.Writer
	now     func() time.Time
}

var _ executor.ExecutorWithReturn[UnlockLogin, bool] = (*UnlockLoginCommand)(nil)

// NewUnlockLogin makes the command.
func NewUnlockLogin(limiter loginlimiter.Limiter, log *slog.Logger) *UnlockLoginCommand {
	if log == nil {
		log = slog.Default()
	}
	return &UnlockLoginCommand{limiter: limiter, log: log, now: func() time.Time { return time.Now().UTC() }}
}

// WithClock sets the clock of the audit entry. The default is time.Now.
func (c *UnlockLoginCommand) WithClock(now func() time.Time) *UnlockLoginCommand {
	if now != nil {
		c.now = now
	}
	return c
}

// WithAudit sets the user repository, the transactor, and the audit writer.
// The command writes an audit entry for each unlock. It does nothing without
// them.
func (c *UnlockLoginCommand) WithAudit(u users.Repository, tx transaction.Transactor, w audit.Writer) *UnlockLoginCommand {
	c.users, c.tx, c.audit = u, tx, w
	return c
}

// Execute normalizes the email with the same rule as the login. Then one
// transaction deletes the counter and writes the audit entry. The transaction
// commits only after the delete works. The entry has the user as target when the
// email belongs to a user, and details.knownUser is false in the other case.
// The log record and the entry have no email.
func (c *UnlockLoginCommand) Execute(ctx context.Context, in UnlockLogin) (bool, error) {
	if c.users == nil || c.tx == nil || c.audit == nil {
		return false, ErrNoAuditWriter
	}
	email, err := domain.NormalizeEmail(in.Email)
	if err != nil {
		email = normalizeLoose(in.Email)
	}
	targetID := ""
	u, err := c.users.GetByEmail(ctx, email)
	switch {
	case err == nil:
		targetID = u.ID
	case errors.Is(err, users.ErrNotFound):
	default:
		return false, fmt.Errorf("find the user: %w", err)
	}
	var unlocked bool
	err = c.tx.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		if unlocked, err = c.limiter.Unlock(ctx, email); err != nil {
			return fmt.Errorf("unlock the login: %w", err)
		}
		return writeAudit(ctx, c.audit, c.now(), ActionLoginUnlock, targetUser, targetID, originDetails(OriginCLI, map[string]any{
			"knownUser": targetID != "", "wasLocked": unlocked,
		}))
	}, txName("unlock_login"))
	if err != nil {
		if unlocked {
			// The counter is deleted and the entry is not committed. The user can
			// log in again, and no entry exists.
			c.log.ErrorContext(ctx, "identity.audit.failed", "event", "identity.audit.failed",
				"action", ActionLoginUnlock, "user_id", targetID)
		}
		return false, err
	}
	c.log.InfoContext(ctx, "identity.login.unlocked", "event", "identity.login.unlocked", "was_locked", unlocked)
	return unlocked, nil
}
