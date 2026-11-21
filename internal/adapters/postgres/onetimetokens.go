package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/onetimetokens"
)

const setupLock = "constellation:identity:first-admin-setup"

// OneTimeTokens is the PostgreSQL repository of the setup tokens and invite
// tokens.
type OneTimeTokens struct {
	pool *pgxpool.Pool
}

var _ onetimetokens.Repository = (*OneTimeTokens)(nil)

// NewOneTimeTokens makes the repository.
func NewOneTimeTokens(pool *pgxpool.Pool) *OneTimeTokens { return &OneTimeTokens{pool: pool} }

// Create adds a token.
func (r *OneTimeTokens) Create(ctx context.Context, t domain.OneTimeToken) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO one_time_tokens (token_hash, purpose, user_id, expires_at, created_at)
		VALUES ($1, $2, NULLIF($3, '')::uuid, $4, $5)`,
		t.Hash, string(t.Purpose), t.UserID, t.ExpiresAt, t.CreatedAt); err != nil {
		return fmt.Errorf("create %s token: %w", t.Purpose, err)
	}
	return nil
}

// Use marks a token as used in one statement. Two parallel calls with one
// token cannot both get a row back.
func (r *OneTimeTokens) Use(ctx context.Context, hash string, purpose domain.TokenPurpose, now time.Time) (string, bool, error) {
	var userID *string
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		UPDATE one_time_tokens SET used_at = $3
		WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3
		RETURNING user_id::text`, hash, string(purpose), now).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("use %s token: %w", purpose, err)
	}
	if userID == nil {
		return "", true, nil
	}
	return *userID, true, nil
}

// IsValid reports whether the token can still be used.
func (r *OneTimeTokens) IsValid(ctx context.Context, hash string, purpose domain.TokenPurpose, now time.Time) (bool, error) {
	var ok bool
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM one_time_tokens
			WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3)`,
		hash, string(purpose), now).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check %s token: %w", purpose, err)
	}
	return ok, nil
}

// FindValid reads a token that can still be used and returns its user ID. The
// read takes no row lock.
func (r *OneTimeTokens) FindValid(ctx context.Context, hash string, purpose domain.TokenPurpose, now time.Time) (string, bool, error) {
	var userID *string
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT user_id::text FROM one_time_tokens
		WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3`,
		hash, string(purpose), now).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("find %s token: %w", purpose, err)
	}
	if userID == nil {
		return "", true, nil
	}
	return *userID, true, nil
}

// HasValidSetup reports whether a setup token can still be used.
func (r *OneTimeTokens) HasValidSetup(ctx context.Context, now time.Time) (bool, error) {
	var ok bool
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM one_time_tokens
			WHERE purpose = 'setup' AND used_at IS NULL AND expires_at > $1)`, now).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check setup tokens: %w", err)
	}
	return ok, nil
}

// DeleteUnusedSetup deletes each unused setup token.
func (r *OneTimeTokens) DeleteUnusedSetup(ctx context.Context) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx,
		`DELETE FROM one_time_tokens WHERE purpose = 'setup' AND used_at IS NULL`); err != nil {
		return fmt.Errorf("delete setup tokens: %w", err)
	}
	return nil
}

// DeleteUnusedInvites deletes each unused invite token of a user.
func (r *OneTimeTokens) DeleteUnusedInvites(ctx context.Context, userID string) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx,
		`DELETE FROM one_time_tokens WHERE purpose = 'invite' AND user_id = $1 AND used_at IS NULL`, userID); err != nil {
		return fmt.Errorf("delete invite tokens: %w", err)
	}
	return nil
}

// WithSetupLock runs fn while this instance holds the setup lock.
func (r *OneTimeTokens) WithSetupLock(ctx context.Context, fn func(ctx context.Context) error) error {
	return withAdvisoryLock(ctx, r.pool, setupLock, fn)
}
