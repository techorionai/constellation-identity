package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/techorionai/constellation-platform-go/retention"
)

// TokenPurger deletes the one-time tokens that ended before the expiry time. A
// token ended when it expired or when it was used, whichever came first.
type TokenPurger struct {
	pool *pgxpool.Pool
}

var _ retention.Purger = (*TokenPurger)(nil)

// NewTokenPurger makes the purger.
func NewTokenPurger(pool *pgxpool.Pool) *TokenPurger { return &TokenPurger{pool: pool} }

// Purge deletes at most params.Limit tokens.
func (p *TokenPurger) Purge(ctx context.Context, params retention.PurgeParams) (int, error) {
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM one_time_tokens WHERE token_hash IN (
			SELECT token_hash FROM one_time_tokens
			WHERE LEAST(expires_at, COALESCE(used_at, expires_at)) < $1
			LIMIT $2 FOR UPDATE SKIP LOCKED)`, params.Before, params.Limit)
	if err != nil {
		return 0, fmt.Errorf("purge tokens: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// SessionPurger deletes the sessions that ended before the expiry time. A
// session ended when it expired or when it was revoked, whichever came first.
type SessionPurger struct {
	pool *pgxpool.Pool
}

var _ retention.Purger = (*SessionPurger)(nil)

// NewSessionPurger makes the purger.
func NewSessionPurger(pool *pgxpool.Pool) *SessionPurger { return &SessionPurger{pool: pool} }

// Purge deletes at most params.Limit sessions.
func (p *SessionPurger) Purge(ctx context.Context, params retention.PurgeParams) (int, error) {
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM sessions WHERE id IN (
			SELECT id FROM sessions
			WHERE LEAST(expires_at, COALESCE(revoked_at, expires_at)) < $1
			LIMIT $2 FOR UPDATE SKIP LOCKED)`, params.Before, params.Limit)
	if err != nil {
		return 0, fmt.Errorf("purge sessions: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// RefreshTokenPurger deletes the refresh tokens that ended before the expiry
// time. A token ended when it expired or when it was used, whichever came
// first.
type RefreshTokenPurger struct {
	pool *pgxpool.Pool
}

var _ retention.Purger = (*RefreshTokenPurger)(nil)

// NewRefreshTokenPurger makes the purger.
func NewRefreshTokenPurger(pool *pgxpool.Pool) *RefreshTokenPurger {
	return &RefreshTokenPurger{pool: pool}
}

// Purge deletes at most params.Limit tokens.
func (p *RefreshTokenPurger) Purge(ctx context.Context, params retention.PurgeParams) (int, error) {
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM refresh_tokens WHERE token_hash IN (
			SELECT token_hash FROM refresh_tokens
			WHERE LEAST(expires_at, COALESCE(used_at, expires_at)) < $1
			LIMIT $2 FOR UPDATE SKIP LOCKED)`, params.Before, params.Limit)
	if err != nil {
		return 0, fmt.Errorf("purge refresh tokens: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// RefreshFamilyPurger deletes the refresh token families that ended before the
// expiry time. A family ended when it was revoked or when its session expired.
type RefreshFamilyPurger struct {
	pool *pgxpool.Pool
}

var _ retention.Purger = (*RefreshFamilyPurger)(nil)

// NewRefreshFamilyPurger makes the purger.
func NewRefreshFamilyPurger(pool *pgxpool.Pool) *RefreshFamilyPurger {
	return &RefreshFamilyPurger{pool: pool}
}

// Purge deletes at most params.Limit families. The tokens of a family go with
// it (ON DELETE CASCADE).
func (p *RefreshFamilyPurger) Purge(ctx context.Context, params retention.PurgeParams) (int, error) {
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM refresh_token_families WHERE id IN (
			SELECT f.id FROM refresh_token_families f JOIN sessions s ON s.id = f.session_id
			WHERE LEAST(s.expires_at, COALESCE(f.revoked_at, s.expires_at)) < $1
			LIMIT $2 FOR UPDATE OF f SKIP LOCKED)`, params.Before, params.Limit)
	if err != nil {
		return 0, fmt.Errorf("purge refresh families: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
