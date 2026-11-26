// Package mfa is the port of the TOTP factors and the recovery codes.
package mfa

import (
	"context"
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Errors of the repository.
var (
	// ErrNotFound means the user has no TOTP factor.
	ErrNotFound = errors.New("totp not found")
	// ErrAlreadyEnabled means the user has a TOTP factor already.
	ErrAlreadyEnabled = errors.New("totp is enabled already")
)

// Repository stores the factors. A call joins the transaction in the context.
type Repository interface {
	// GetTOTP returns the factor, or an error that wraps ErrNotFound.
	GetTOTP(ctx context.Context, userID string) (domain.TOTPRecord, error)
	// EnableTOTP adds the factor and replaces the recovery codes of the user with
	// the hashes in one transaction. It returns an error that wraps
	// ErrAlreadyEnabled if the user has a factor.
	EnableTOTP(ctx context.Context, rec domain.TOTPRecord, codeHashes [][]byte, now time.Time) error
	// AdvanceStep sets last_used_step and last_used_at in one statement that
	// needs last_used_step to be less than step. It returns false if no row
	// changed (a replay, or no factor).
	AdvanceStep(ctx context.Context, userID string, step int64, now time.Time) (bool, error)
	// UseRecoveryCode sets used_at of the unused code with the hash. It returns
	// false if no row changed.
	UseRecoveryCode(ctx context.Context, userID string, hash []byte, now time.Time) (bool, error)
	// ReplaceRecoveryCodes deletes all codes of the user and adds the new
	// hashes in one transaction.
	ReplaceRecoveryCodes(ctx context.Context, userID string, hashes [][]byte, now time.Time) error
	// State returns the MFA data of the user.
	State(ctx context.Context, userID string) (domain.MFAState, error)
	// RemoveAll deletes the factor and all recovery codes of the user. It
	// returns true if a TOTP factor existed.
	RemoveAll(ctx context.Context, userID string) (hadTOTP bool, err error)
}
