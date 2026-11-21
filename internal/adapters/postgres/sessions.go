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
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
)

// Sessions is the PostgreSQL repository of the browser sessions.
type Sessions struct {
	pool *pgxpool.Pool
}

var _ sessions.Repository = (*Sessions)(nil)

// NewSessions makes the repository.
func NewSessions(pool *pgxpool.Pool) *Sessions { return &Sessions{pool: pool} }

// Create adds a session.
func (r *Sessions) Create(ctx context.Context, s domain.Session) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at, user_agent, ip_address)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		s.ID, s.UserID, s.TokenHash, s.CreatedAt, s.LastSeenAt, s.IdleExpiresAt, s.ExpiresAt, s.UserAgent, s.IPAddress); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// GetByTokenHash returns a session.
func (r *Sessions) GetByTokenHash(ctx context.Context, hash string) (domain.Session, error) {
	var s domain.Session
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at, revoked_at, user_agent, ip_address
		FROM sessions WHERE token_hash = $1`, hash).
		Scan(&s.ID, &s.UserID, &s.TokenHash, &s.CreatedAt, &s.LastSeenAt, &s.IdleExpiresAt, &s.ExpiresAt, &s.RevokedAt, &s.UserAgent, &s.IPAddress)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Session{}, fmt.Errorf("get session: %w", sessions.ErrNotFound)
	}
	if err != nil {
		return domain.Session{}, fmt.Errorf("get session: %w", err)
	}
	return s, nil
}

// Touch sets the last seen time and the idle expiry.
func (r *Sessions) Touch(ctx context.Context, id string, lastSeen, idleExpires time.Time) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE sessions SET last_seen_at = $2, idle_expires_at = $3
		WHERE id = $1 AND revoked_at IS NULL`, id, lastSeen, idleExpires); err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

// RevokeByTokenHash revokes a session.
func (r *Sessions) RevokeByTokenHash(ctx context.Context, hash string, now time.Time) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE sessions SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL`, hash, now); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// CountActive returns the number of valid sessions.
func (r *Sessions) CountActive(ctx context.Context, now time.Time) (int64, error) {
	var n int64
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT count(*) FROM sessions
		WHERE revoked_at IS NULL AND idle_expires_at > $1 AND expires_at > $1`, now).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}
	return n, nil
}
