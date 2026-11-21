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
