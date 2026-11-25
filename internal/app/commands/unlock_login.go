package commands

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/techorionai/constellation-platform-go/executor"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/loginlimiter"
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
}

var _ executor.ExecutorWithReturn[UnlockLogin, bool] = (*UnlockLoginCommand)(nil)

// NewUnlockLogin makes the command.
func NewUnlockLogin(limiter loginlimiter.Limiter, log *slog.Logger) *UnlockLoginCommand {
	if log == nil {
		log = slog.Default()
	}
	return &UnlockLoginCommand{limiter: limiter, log: log}
}

// Execute normalizes the email with the same rule as the login, then deletes the
// counter. The log record has no email.
func (c *UnlockLoginCommand) Execute(ctx context.Context, in UnlockLogin) (bool, error) {
	email, err := domain.NormalizeEmail(in.Email)
	if err != nil {
		email = normalizeLoose(in.Email)
	}
	unlocked, err := c.limiter.Unlock(ctx, email)
	if err != nil {
		return false, fmt.Errorf("unlock the login: %w", err)
	}
	c.log.InfoContext(ctx, "identity.login.unlocked", "event", "identity.login.unlocked", "was_locked", unlocked)
	return unlocked, nil
}
