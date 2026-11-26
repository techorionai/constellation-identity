package commands

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/mfaflow"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// CeremonyTypeConfirm is the value of the attribute type of the metric
// identity.passkey.ceremonies for the proof of a passkey before a link or a
// link removal (P23).
const CeremonyTypeConfirm = "confirm"

// BeginPasskeyConfirm makes the options of the passkey check that a link and a
// link removal need (P23). The state of the ceremony is bound to the hash of the
// session cookie, so only the same session can finish it. It returns
// ErrPasskeysOff if the service does not accept passkeys, and ErrPasskeyInvalid
// for a user with no passkey.
func (m *MFA) BeginPasskeyConfirm(ctx context.Context, userID, sessionHash string) ([]byte, error) {
	if !m.passkeysReady() {
		return nil, ErrPasskeysOff
	}
	user, err := m.d.Users.GetByID(ctx, userID)
	if errors.Is(err, users.ErrNotFound) || (err == nil && user.Status != domain.UserActive) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get the user: %w", err)
	}
	creds, err := m.d.Passkeys.Credentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list the passkeys: %w", err)
	}
	if len(creds) == 0 {
		return nil, ErrPasskeyInvalid
	}
	wu, err := m.webauthnUser(ctx, user)
	if err != nil {
		return nil, err
	}
	opts, err := m.d.WebAuthn.BeginSecondFactor(ctx, wu, portCredentials(creds))
	if err != nil {
		return nil, err
	}
	err = m.d.Ceremonies.Put(ctx, mfaflow.CeremonyConfirm, sessionHash, domain.Ceremony{State: opts.State, UserID: userID}, CeremonyTTL)
	if err != nil {
		return nil, m.unavailable(ctx, "store the passkey check state", err)
	}
	return opts.JSON, nil
}

// PasskeyConfirm is the input of the end of the passkey check.
type PasskeyConfirm struct {
	UserID      string
	SessionHash string
	// Body is the response of the browser.
	Body []byte
}

// FinishPasskeyConfirm checks the response of a passkey for the user. It uses
// the failure counters of the second factor, so a guess loop is limited. It
// returns nil if the passkey is good. The errors: ErrPasskeysOff,
// ErrTooManyAttempts, ErrPasskeyInvalid (also for a state that is gone or that
// belongs to another user), and ErrMFAUnavailable.
func (m *MFA) FinishPasskeyConfirm(ctx context.Context, in PasskeyConfirm) error {
	if !m.passkeysReady() {
		return ErrPasskeysOff
	}
	limited, err := m.reserveFailure(ctx, in.UserID)
	if err != nil {
		return err
	}
	if limited {
		m.count(ctx, methodHWK, MFAOutcomeLimited)
		m.ceremony(ctx, CeremonyTypeConfirm, CeremonyOutcomeLimited)
		return ErrTooManyAttempts
	}
	bad := func(outcome string) error {
		m.ceremony(ctx, CeremonyTypeConfirm, outcome)
		m.count(ctx, methodHWK, MFAOutcomeBadCode)
		m.d.Log.InfoContext(ctx, "identity.mfa.failed", "event", "identity.mfa.failed", "user_id", in.UserID, "method", methodHWK, "outcome", outcome)
		return ErrPasskeyInvalid
	}
	user, err := m.d.Users.GetByID(ctx, in.UserID)
	if errors.Is(err, users.ErrNotFound) || (err == nil && user.Status != domain.UserActive) {
		return bad(CeremonyOutcomeExpired)
	}
	if err != nil {
		return fmt.Errorf("get the user: %w", err)
	}
	cer, err := m.d.Ceremonies.Take(ctx, mfaflow.CeremonyConfirm, in.SessionHash)
	if errors.Is(err, mfaflow.ErrNotFound) || (err == nil && cer.UserID != in.UserID) {
		return bad(CeremonyOutcomeExpired)
	}
	if err != nil {
		return m.unavailable(ctx, "take the passkey check state", err)
	}
	creds, err := m.d.Passkeys.Credentials(ctx, in.UserID)
	if err != nil {
		return fmt.Errorf("list the passkeys: %w", err)
	}
	wu, err := m.webauthnUser(ctx, user)
	if err != nil {
		return err
	}
	res, err := m.d.WebAuthn.FinishSecondFactor(ctx, wu, portCredentials(creds), cer.State, in.Body)
	if err != nil {
		return bad(ceremonyOutcome(err))
	}
	idx := slices.IndexFunc(creds, func(c domain.PasskeyCredential) bool { return string(c.CredentialID) == string(res.CredentialID) })
	if idx < 0 {
		return bad(CeremonyOutcomeUnknownCredential)
	}
	cred := creds[idx]
	if !domain.SignCountAccepted(cred.SignCount, res.SignCount) {
		m.cloneWarning(ctx, in.UserID)
		return bad(CeremonyOutcomeCloneWarning)
	}
	advanced, err := m.d.Passkeys.AdvanceSignCount(ctx, cred.ID, res.SignCount, res.BackupState, m.now())
	if err != nil {
		return fmt.Errorf("advance the sign count: %w", err)
	}
	if !advanced {
		m.cloneWarning(ctx, in.UserID)
		return bad(CeremonyOutcomeCloneWarning)
	}
	m.releaseFailure(ctx, in.UserID)
	m.count(ctx, methodHWK, MFAOutcomeOK)
	m.ceremony(ctx, CeremonyTypeConfirm, CeremonyOutcomeOK)
	return nil
}
