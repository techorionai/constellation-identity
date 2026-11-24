package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"
	"github.com/techorionai/constellation-platform-go/retention"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/apitokens"
)

// APITokens is the PostgreSQL repository of the personal API tokens.
type APITokens struct {
	pool *pgxpool.Pool
}

var _ apitokens.Repository = (*APITokens)(nil)

// NewAPITokens makes the repository.
func NewAPITokens(pool *pgxpool.Pool) *APITokens { return &APITokens{pool: pool} }

//nolint:gosec // A list of column names, not a credential.
const apiTokenColumns = `t.id, t.user_id, t.name, t.scope, t.created_at, t.expires_at, t.last_used_at, t.revoked_at`

func scanAPIToken(row pgx.Row, extra ...any) (domain.APIToken, error) {
	var (
		t     domain.APIToken
		scope string
	)
	dest := append([]any{&t.ID, &t.UserID, &t.Name, &scope, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt}, extra...)
	if err := row.Scan(dest...); err != nil {
		return domain.APIToken{}, err
	}
	t.Scope = strings.Fields(scope)
	return t, nil
}

// Insert adds a token.
func (r *APITokens) Insert(ctx context.Context, hash string, t domain.APIToken) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO api_tokens (id, token_hash, user_id, name, scope, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		t.ID, hash, t.UserID, t.Name, strings.Join(t.Scope, " "), t.CreatedAt, t.ExpiresAt); err != nil {
		return fmt.Errorf("insert api token: %w", err)
	}
	return nil
}

// CountActive counts the active tokens of a user.
func (r *APITokens) CountActive(ctx context.Context, userID string, now time.Time) (int, error) {
	var n int
	if err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT count(*) FROM api_tokens
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2`, userID, now).Scan(&n); err != nil {
		return 0, fmt.Errorf("count active api tokens: %w", err)
	}
	return n, nil
}

// CountAll counts all rows of a user.
func (r *APITokens) CountAll(ctx context.Context, userID string) (int, error) {
	var n int
	if err := clientspg.Conn(ctx, r.pool).QueryRow(ctx,
		`SELECT count(*) FROM api_tokens WHERE user_id = $1`, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count api tokens: %w", err)
	}
	return n, nil
}

// ListByUser returns a page of the tokens of a user, newest first.
func (r *APITokens) ListByUser(ctx context.Context, userID string, after *domain.PageCursor, limit int) ([]domain.APIToken, error) {
	query := `SELECT ` + apiTokenColumns + ` FROM api_tokens t WHERE t.user_id = $1`
	args := []any{userID}
	if after != nil {
		query += ` AND (t.created_at, t.id) < ($2, $3::uuid)`
		args = append(args, after.CreatedAt, after.ID)
	}
	query += ` ORDER BY t.created_at DESC, t.id DESC LIMIT ` + fmt.Sprint(limit)
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()
	var out []domain.APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	return out, nil
}

// GetByHash returns a token and the status of its user.
func (r *APITokens) GetByHash(ctx context.Context, hash string) (domain.APITokenWithOwner, error) {
	var status string
	t, err := scanAPIToken(clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT `+apiTokenColumns+`, u.status
		FROM api_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1`, hash), &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.APITokenWithOwner{}, fmt.Errorf("get api token: %w", apitokens.ErrNotFound)
	}
	if err != nil {
		return domain.APITokenWithOwner{}, fmt.Errorf("get api token: %w", err)
	}
	return domain.APITokenWithOwner{APIToken: t, OwnerStatus: domain.UserStatus(status)}, nil
}

// Revoke sets revoked_at of a token. A token that is revoked already is found
// and does not change.
func (r *APITokens) Revoke(ctx context.Context, id, owner string, now time.Time) (bool, error) {
	query := `WITH t AS (SELECT id FROM api_tokens WHERE id = $1`
	args := []any{id, now}
	if owner != "" {
		query += ` AND user_id = $3`
		args = append(args, owner)
	}
	query += `), u AS (UPDATE api_tokens SET revoked_at = $2 WHERE id IN (SELECT id FROM t) AND revoked_at IS NULL)
		SELECT count(*) FROM t`
	var n int
	if err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return false, fmt.Errorf("revoke api token: %w", err)
	}
	return n == 1, nil
}

// RevokeAllOfUser revokes the active tokens of a user.
func (r *APITokens) RevokeAllOfUser(ctx context.Context, userID string, now time.Time) (int, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE api_tokens SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2`, userID, now)
	if err != nil {
		return 0, fmt.Errorf("revoke api tokens of user: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// TouchLastUsed sets last_used_at with one conditional UPDATE.
func (r *APITokens) TouchLastUsed(ctx context.Context, id string, now time.Time, interval time.Duration) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE api_tokens SET last_used_at = $2
		WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < $3)`, id, now, now.Add(-interval)); err != nil {
		return fmt.Errorf("touch api token: %w", err)
	}
	return nil
}

// APITokenPurger deletes the API tokens that ended before the expiry time. A
// token ended when it expired or when it was revoked, whichever came first.
type APITokenPurger struct {
	pool *pgxpool.Pool
}

var _ retention.Purger = (*APITokenPurger)(nil)

// NewAPITokenPurger makes the purger.
func NewAPITokenPurger(pool *pgxpool.Pool) *APITokenPurger { return &APITokenPurger{pool: pool} }

// Purge deletes at most params.Limit tokens.
func (p *APITokenPurger) Purge(ctx context.Context, params retention.PurgeParams) (int, error) {
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM api_tokens WHERE id IN (
			SELECT id FROM api_tokens
			WHERE LEAST(expires_at, COALESCE(revoked_at, expires_at)) < $1
			LIMIT $2 FOR UPDATE SKIP LOCKED)`, params.Before, params.Limit)
	if err != nil {
		return 0, fmt.Errorf("purge api tokens: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
