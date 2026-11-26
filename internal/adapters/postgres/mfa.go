package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/mfa"
)

// MFA is the PostgreSQL repository of the TOTP factors and the recovery codes.
type MFA struct {
	pool *pgxpool.Pool
}

var _ mfa.Repository = (*MFA)(nil)

// NewMFA makes the repository.
func NewMFA(pool *pgxpool.Pool) *MFA { return &MFA{pool: pool} }

// GetTOTP returns the TOTP factor of a user.
func (r *MFA) GetTOTP(ctx context.Context, userID string) (domain.TOTPRecord, error) {
	rec := domain.TOTPRecord{UserID: userID}
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT secret, key_id, last_used_step, created_at, last_used_at FROM user_totp WHERE user_id = $1`, userID).
		Scan(&rec.Secret, &rec.KeyID, &rec.LastUsedStep, &rec.CreatedAt, &rec.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TOTPRecord{}, fmt.Errorf("get totp: %w", mfa.ErrNotFound)
	}
	if err != nil {
		return domain.TOTPRecord{}, fmt.Errorf("get totp: %w", err)
	}
	return rec, nil
}

func insertCodes(ctx context.Context, q clientspg.Querier, userID string, hashes [][]byte, now time.Time) error {
	for _, h := range hashes {
		if _, err := q.Exec(ctx, `
			INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES ($1, $2, $3, $4)`,
			uuid.NewString(), userID, h, now); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return nil
}

// EnableTOTP adds the factor and replaces the recovery codes in one transaction.
func (r *MFA) EnableTOTP(ctx context.Context, rec domain.TOTPRecord, codeHashes [][]byte, now time.Time) error {
	return inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		if _, err := q.Exec(ctx, `
			INSERT INTO user_totp (user_id, secret, key_id, last_used_step, created_at) VALUES ($1, $2, $3, $4, $5)`,
			rec.UserID, rec.Secret, rec.KeyID, rec.LastUsedStep, rec.CreatedAt); err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.Code == "23505" {
				return fmt.Errorf("enable totp: %w", mfa.ErrAlreadyEnabled)
			}
			return fmt.Errorf("enable totp: %w", err)
		}
		if _, err := q.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, rec.UserID); err != nil {
			return fmt.Errorf("delete recovery codes: %w", err)
		}
		return insertCodes(ctx, q, rec.UserID, codeHashes, now)
	})
}

// AdvanceStep sets the last used step if it is less than step.
func (r *MFA) AdvanceStep(ctx context.Context, userID string, step int64, now time.Time) (bool, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE user_totp SET last_used_step = $2, last_used_at = $3
		WHERE user_id = $1 AND last_used_step < $2`, userID, step, now)
	if err != nil {
		return false, fmt.Errorf("advance totp step: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// UseRecoveryCode sets used_at of an unused code.
func (r *MFA) UseRecoveryCode(ctx context.Context, userID string, hash []byte, now time.Time) (bool, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE recovery_codes SET used_at = $3 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
		userID, hash, now)
	if err != nil {
		return false, fmt.Errorf("use recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ReplaceRecoveryCodes deletes all codes of the user and adds the new set.
func (r *MFA) ReplaceRecoveryCodes(ctx context.Context, userID string, hashes [][]byte, now time.Time) error {
	return inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		if _, err := q.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
			return fmt.Errorf("delete recovery codes: %w", err)
		}
		return insertCodes(ctx, q, userID, hashes, now)
	})
}

// State returns the MFA data of a user.
func (r *MFA) State(ctx context.Context, userID string) (domain.MFAState, error) {
	var st domain.MFAState
	q := clientspg.Conn(ctx, r.pool)
	err := q.QueryRow(ctx, `SELECT created_at, last_used_at FROM user_totp WHERE user_id = $1`, userID).
		Scan(&st.TOTPAt, &st.LastUsedAt)
	switch {
	case err == nil:
		st.HasTOTP = true
	case errors.Is(err, pgx.ErrNoRows):
	default:
		return domain.MFAState{}, fmt.Errorf("read totp state: %w", err)
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID).
		Scan(&st.CodesRemaining); err != nil {
		return domain.MFAState{}, fmt.Errorf("count recovery codes: %w", err)
	}
	return st, nil
}

// RemoveAll deletes the factor and the recovery codes.
func (r *MFA) RemoveAll(ctx context.Context, userID string) (bool, error) {
	had := false
	err := inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		tag, err := q.Exec(ctx, `DELETE FROM user_totp WHERE user_id = $1`, userID)
		if err != nil {
			return fmt.Errorf("delete totp: %w", err)
		}
		had = tag.RowsAffected() == 1
		if _, err := q.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
			return fmt.Errorf("delete recovery codes: %w", err)
		}
		return nil
	})
	return had, err
}
