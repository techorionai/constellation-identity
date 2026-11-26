package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// Errors of the check of a local factor (P23).
var (
	// ErrLocalFactorRequired means the user has a local factor and the request
	// did not prove it. The password or the code is missing or wrong.
	ErrLocalFactorRequired = errors.New("a local factor is necessary")
	// ErrLocalFactorMissing means the user has no local factor that the check
	// can use. A user with no password, no TOTP, and no passkey has none. A user
	// with only a passkey also gets this error, because the check accepts a
	// password and a code only.
	ErrLocalFactorMissing = errors.New("the user has no password or code to check")
)

// LocalFactor is the input of the check of a local factor.
type LocalFactor struct {
	UserID string
	// Password and Code are secrets. The password is the password of the user.
	// The code is a TOTP code or a recovery code. One of them is enough.
	Password string
	Code     string
}

// HasLocalFactor reports whether the user has a local factor: a password, a TOTP
// factor, or a passkey that the service accepts.
func (m *MFA) HasLocalFactor(ctx context.Context, userID string) (bool, error) {
	u, err := m.d.Users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			return false, ErrUserNotFound
		}
		return false, fmt.Errorf("get the user: %w", err)
	}
	st, err := m.state(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("read the MFA state: %w", err)
	}
	return domain.HasLocalFactor(u.PasswordHash != "", st), nil
}

// VerifyLocalFactor checks that the person at the request knows a local factor
// of the user: the password, a TOTP code, or a recovery code. It is the proof
// that a link and a link removal need (P23). It uses the failure counters of
// the second factor, so a guess loop is limited. It returns
// ErrLocalFactorMissing for a user with nothing to check, ErrTooManyAttempts at
// the limit, and ErrLocalFactorRequired for a missing or wrong value.
func (m *MFA) VerifyLocalFactor(ctx context.Context, in LocalFactor) error {
	u, err := m.d.Users.GetByID(ctx, in.UserID)
	if errors.Is(err, users.ErrNotFound) || (err == nil && u.Status != domain.UserActive) {
		return ErrUserNotFound
	}
	if err != nil {
		return fmt.Errorf("get the user: %w", err)
	}
	st, err := m.state(ctx, u.ID)
	if err != nil {
		return fmt.Errorf("read the MFA state: %w", err)
	}
	canPassword := u.PasswordHash != "" && m.d.Hasher != nil
	canCode := st.HasTOTP || st.CodesRemaining > 0
	if !canPassword && !canCode {
		return ErrLocalFactorMissing
	}
	limited, err := m.reserveFailure(ctx, u.ID)
	if err != nil {
		return err
	}
	if limited {
		m.count(ctx, "local_factor", MFAOutcomeLimited)
		return ErrTooManyAttempts
	}
	ok, err := m.checkLocalFactor(ctx, u, in, canPassword, canCode)
	if err != nil {
		return err
	}
	if !ok {
		m.count(ctx, "local_factor", MFAOutcomeBadCode)
		m.d.Log.InfoContext(ctx, "identity.mfa.failed", "event", "identity.mfa.failed", "user_id", u.ID, "method", "local_factor", "outcome", MFAOutcomeBadCode)
		return ErrLocalFactorRequired
	}
	m.releaseFailure(ctx, u.ID)
	m.count(ctx, "local_factor", MFAOutcomeOK)
	return nil
}

// checkLocalFactor does the check and uses the code. It returns false for a
// value that is missing or wrong.
func (m *MFA) checkLocalFactor(ctx context.Context, u domain.User, in LocalFactor, canPassword, canCode bool) (bool, error) {
	if canPassword && in.Password != "" {
		good, _, err := m.d.Hasher.Verify(ctx, m.d.Hasher.Normalize(in.Password), u.PasswordHash)
		if err != nil {
			return false, fmt.Errorf("verify the password: %w", err)
		}
		if good {
			return true, nil
		}
	}
	if !canCode || in.Code == "" {
		return false, nil
	}
	consume, err := m.checkTOTP(ctx, u.ID, in.Code)
	if err != nil && !errors.Is(err, ErrMFAReplay) {
		return false, err
	}
	if consume == nil {
		consume, err = m.checkRecovery(ctx, u.ID, in.Code)
		if err != nil {
			return false, err
		}
	}
	if consume == nil {
		return false, nil
	}
	used, err := consume(ctx)
	if err != nil {
		return false, err
	}
	return used, nil
}
