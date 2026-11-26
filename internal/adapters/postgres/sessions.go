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

const sessionColumns = `id, user_id, token_hash, created_at, auth_time, amr, last_seen_at, idle_expires_at, expires_at, revoked_at, user_agent, ip_address`

func scanSession(row pgx.Row) (domain.Session, error) {
	var s domain.Session
	err := row.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.CreatedAt, &s.AuthTime, &s.AuthMethods, &s.LastSeenAt, &s.IdleExpiresAt, &s.ExpiresAt, &s.RevokedAt, &s.UserAgent, &s.IPAddress)
	return s, err
}

// Create adds a session. The service always sets auth_time and does not use
// the default of the column.
func (r *Sessions) Create(ctx context.Context, s domain.Session) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, created_at, auth_time, amr, last_seen_at, idle_expires_at, expires_at, user_agent, ip_address)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		s.ID, s.UserID, s.TokenHash, s.CreatedAt, s.AuthTime, nonNil(s.AuthMethods), s.LastSeenAt, s.IdleExpiresAt, s.ExpiresAt, s.UserAgent, s.IPAddress); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// GetByTokenHash returns a session.
func (r *Sessions) GetByTokenHash(ctx context.Context, hash string) (domain.Session, error) {
	s, err := scanSession(clientspg.Conn(ctx, r.pool).QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE token_hash = $1`, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Session{}, fmt.Errorf("get session: %w", sessions.ErrNotFound)
	}
	if err != nil {
		return domain.Session{}, fmt.Errorf("get session: %w", err)
	}
	return s, nil
}

// GetByID returns a session.
func (r *Sessions) GetByID(ctx context.Context, id string) (domain.Session, error) {
	s, err := scanSession(clientspg.Conn(ctx, r.pool).QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Session{}, fmt.Errorf("get session: %w", sessions.ErrNotFound)
	}
	if err != nil {
		return domain.Session{}, fmt.Errorf("get session: %w", err)
	}
	return s, nil
}

// ListByUser returns a page of the sessions of a user.
func (r *Sessions) ListByUser(ctx context.Context, userID string, now time.Time, after *domain.PageCursor, limit int) ([]domain.Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2 AND idle_expires_at > $2`
	args := []any{userID, now}
	if after != nil {
		query += ` AND (created_at, id) > ($3, $4::uuid)`
		args = append(args, after.CreatedAt, after.ID)
	}
	query += ` ORDER BY created_at, id LIMIT ` + fmt.Sprint(limit)
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()
	var out []domain.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return out, nil
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

// Reauthenticate replaces the token hash and sets the auth time in one UPDATE.
// The WHERE clause is the rule of a valid session, so a parallel revoke makes
// the statement change no row.
func (r *Sessions) Reauthenticate(ctx context.Context, a sessions.Reauth) (string, bool, error) {
	var id string
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		UPDATE sessions
		SET token_hash = $2, auth_time = $4, amr = $8, last_seen_at = $4, idle_expires_at = $5, user_agent = $6, ip_address = $7
		WHERE token_hash = $1 AND user_id = $3 AND revoked_at IS NULL AND expires_at > $4 AND idle_expires_at > $4
		RETURNING id`,
		a.OldHash, a.NewHash, a.UserID, a.Now, a.IdleExpires, a.UserAgent, a.IPAddress, nonNil(a.Methods)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reauthenticate session: %w", err)
	}
	return id, true, nil
}

// nonNil gives an empty list for nil. The column amr is NOT NULL.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// SetMethods replaces the methods of a session that is not revoked.
func (r *Sessions) SetMethods(ctx context.Context, id string, methods []string) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE sessions SET amr = $2 WHERE id = $1 AND revoked_at IS NULL`, id, nonNil(methods)); err != nil {
		return fmt.Errorf("set session methods: %w", err)
	}
	return nil
}

// DropSecondFactor removes the methods of the second factor from the sessions
// and the refresh token families of a user.
func (r *Sessions) DropSecondFactor(ctx context.Context, userID string) error {
	drop := []string{domain.AMROTP, domain.AMRRecovery, domain.AMRMFA}
	return inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		for _, table := range []string{"sessions", "refresh_token_families"} {
			if _, err := q.Exec(ctx, `UPDATE `+table+` SET amr = ARRAY(SELECT m FROM unnest(amr) AS m WHERE m <> ALL($2::text[]))
				WHERE user_id = $1 AND revoked_at IS NULL`, userID, drop); err != nil {
				return fmt.Errorf("drop second factor from %s: %w", table, err)
			}
		}
		return nil
	})
}

// RevokeByTokenHash revokes a session.
func (r *Sessions) RevokeByTokenHash(ctx context.Context, hash string, now time.Time) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE sessions SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL`, hash, now); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// inTx runs fn in the transaction of the context. If the context has none, it
// makes one.
func inTx(ctx context.Context, pool *pgxpool.Pool, fn func(ctx context.Context, q clientspg.Querier) error) error {
	if tx, ok := clientspg.TxFromContext(ctx); ok {
		return fn(ctx, tx)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// RevokeCascade revokes a session and its families. The session row is locked
// first. Then the family rows are locked in ascending ID order.
func (r *Sessions) RevokeCascade(ctx context.Context, id string, now time.Time) (bool, error) {
	found := false
	err := inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		var one string
		err := q.QueryRow(ctx, `SELECT id FROM sessions WHERE id = $1 FOR UPDATE`, id).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("lock session: %w", err)
		}
		found = true
		return revokeSessions(ctx, q, []string{id}, now)
	})
	return found, err
}

// RevokeAllOfUser revokes all sessions of a user and their families.
func (r *Sessions) RevokeAllOfUser(ctx context.Context, userID string, now time.Time) (int, error) {
	n := 0
	err := inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		rows, err := q.Query(ctx, `SELECT id FROM sessions WHERE user_id = $1 ORDER BY id FOR UPDATE`, userID)
		if err != nil {
			return fmt.Errorf("lock sessions: %w", err)
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("scan session id: %w", err)
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("lock sessions: %w", err)
		}
		if len(ids) == 0 {
			return nil
		}
		tag, err := q.Exec(ctx, `UPDATE sessions SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`, userID, now)
		if err != nil {
			return fmt.Errorf("revoke sessions: %w", err)
		}
		n = int(tag.RowsAffected())
		return revokeFamilies(ctx, q, `session_id = ANY($1::uuid[])`, ids, now)
	})
	return n, err
}

func revokeSessions(ctx context.Context, q clientspg.Querier, ids []string, now time.Time) error {
	if _, err := q.Exec(ctx, `UPDATE sessions SET revoked_at = $2 WHERE id = ANY($1::uuid[]) AND revoked_at IS NULL`, ids, now); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return revokeFamilies(ctx, q, `session_id = ANY($1::uuid[])`, ids, now)
}

// revokeFamilies locks the families that the condition selects in ascending ID
// order, then revokes them.
func revokeFamilies(ctx context.Context, q clientspg.Querier, cond string, arg any, now time.Time) error {
	rows, err := q.Query(ctx, `SELECT id FROM refresh_token_families WHERE `+cond+` ORDER BY id FOR UPDATE`, arg)
	if err != nil {
		return fmt.Errorf("lock families: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("scan family id: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("lock families: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}
	if _, err := q.Exec(ctx, `UPDATE refresh_token_families SET revoked_at = $2 WHERE id = ANY($1::uuid[]) AND revoked_at IS NULL`, ids, now); err != nil {
		return fmt.Errorf("revoke families: %w", err)
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
