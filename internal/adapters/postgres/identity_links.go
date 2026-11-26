package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/identitylinks"
)

// IdentityLinks is the PostgreSQL repository of the upstream links.
type IdentityLinks struct {
	pool *pgxpool.Pool
}

var _ identitylinks.Repository = (*IdentityLinks)(nil)

// NewIdentityLinks makes the repository.
func NewIdentityLinks(pool *pgxpool.Pool) *IdentityLinks { return &IdentityLinks{pool: pool} }

const linkColumns = `id, user_id, provider, subject, COALESCE(email, ''), created_at, last_used_at`

func scanLink(row pgx.Row) (domain.IdentityLink, error) {
	var l domain.IdentityLink
	err := row.Scan(&l.ID, &l.UserID, &l.Provider, &l.Subject, &l.Email, &l.CreatedAt, &l.LastUsedAt)
	return l, err
}

// Create adds a link.
func (r *IdentityLinks) Create(ctx context.Context, l domain.IdentityLink) error {
	_, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO identity_links (id, user_id, provider, subject, email, created_at)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6)`,
		l.ID, l.UserID, l.Provider, l.Subject, l.Email, l.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		switch pgErr.ConstraintName {
		case "identity_links_provider_subject_key":
			return fmt.Errorf("create link: %w", identitylinks.ErrSubjectLinked)
		case "identity_links_user_id_provider_key":
			return fmt.Errorf("create link: %w", identitylinks.ErrProviderLinked)
		}
	}
	if err != nil {
		return fmt.Errorf("create link: %w", err)
	}
	return nil
}

func (r *IdentityLinks) get(ctx context.Context, query string, args ...any) (domain.IdentityLink, error) {
	l, err := scanLink(clientspg.Conn(ctx, r.pool).QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.IdentityLink{}, fmt.Errorf("get link: %w", identitylinks.ErrNotFound)
	}
	if err != nil {
		return domain.IdentityLink{}, fmt.Errorf("get link: %w", err)
	}
	return l, nil
}

// GetBySubject returns the link of an upstream account.
func (r *IdentityLinks) GetBySubject(ctx context.Context, provider, subject string) (domain.IdentityLink, error) {
	return r.get(ctx, `SELECT `+linkColumns+` FROM identity_links WHERE provider = $1 AND subject = $2`, provider, subject)
}

// GetByUserProvider returns the link of a user for a provider.
func (r *IdentityLinks) GetByUserProvider(ctx context.Context, userID, provider string) (domain.IdentityLink, error) {
	return r.get(ctx, `SELECT `+linkColumns+` FROM identity_links WHERE user_id = $1 AND provider = $2`, userID, provider)
}

// ListByUser returns a page of the links of a user.
func (r *IdentityLinks) ListByUser(ctx context.Context, userID string, after *domain.PageCursor, limit int) ([]domain.IdentityLink, error) {
	query := `SELECT ` + linkColumns + ` FROM identity_links WHERE user_id = $1`
	args := []any{userID}
	if after != nil {
		query += ` AND (created_at, provider) > ($2, $3)`
		args = append(args, after.CreatedAt, after.ID)
	}
	query += ` ORDER BY created_at ASC, provider ASC LIMIT ` + fmt.Sprint(limit)
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	defer rows.Close()
	var out []domain.IdentityLink
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, fmt.Errorf("scan link: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	return out, nil
}

// Remove deletes the link of a user for a provider.
func (r *IdentityLinks) Remove(ctx context.Context, userID, provider string) error {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx,
		`DELETE FROM identity_links WHERE user_id = $1 AND provider = $2`, userID, provider)
	if err != nil {
		return fmt.Errorf("remove link: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("remove link: %w", identitylinks.ErrNotFound)
	}
	return nil
}

// Touch sets the last use time and the email of a link.
func (r *IdentityLinks) Touch(ctx context.Context, id, email string, now time.Time) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx,
		`UPDATE identity_links SET last_used_at = $3, email = NULLIF($2, '') WHERE id = $1`, id, email, now); err != nil {
		return fmt.Errorf("touch link: %w", err)
	}
	return nil
}

// CountUsersWithoutLoginMethod counts the active users with no login method.
func (r *IdentityLinks) CountUsersWithoutLoginMethod(ctx context.Context, providersOn []string, passkeysOn bool) (int, error) {
	if providersOn == nil {
		providersOn = []string{}
	}
	var n int
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT count(*) FROM users u
		WHERE u.status = 'active' AND u.password_hash IS NULL
		  AND NOT ($2::boolean AND EXISTS (SELECT 1 FROM webauthn_credentials c WHERE c.user_id = u.id))
		  AND NOT EXISTS (SELECT 1 FROM identity_links l WHERE l.user_id = u.id AND l.provider = ANY($1::text[]))`,
		providersOn, passkeysOn).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count users without a login method: %w", err)
	}
	return n, nil
}
