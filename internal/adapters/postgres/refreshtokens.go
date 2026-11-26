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

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/refreshtokens"
)

// RefreshTokens is the PostgreSQL repository of the refresh token families and
// tokens. Each call joins the transaction in the context.
type RefreshTokens struct {
	pool *pgxpool.Pool
}

var _ refreshtokens.Repository = (*RefreshTokens)(nil)

// NewRefreshTokens makes the repository.
func NewRefreshTokens(pool *pgxpool.Pool) *RefreshTokens { return &RefreshTokens{pool: pool} }

// InsertFamilyIfSessionValid adds the family and the first token in one
// statement. The INSERT ... SELECT checks the session and locks its row, so no
// row exists for a session that ended, and a parallel revoke of the session
// waits until the insert commits.
func (r *RefreshTokens) InsertFamilyIfSessionValid(ctx context.Context, f domain.RefreshFamily, t domain.RefreshToken, now time.Time) (bool, error) {
	var id string
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		WITH fam AS (
			INSERT INTO refresh_token_families (id, session_id, client_id, user_id, scope, oidc_scopes, created_at, auth_time, amr)
			SELECT $1, s.id, $3, $4, $5, $6, $7, $11::timestamptz, $12::text[] FROM sessions s
			WHERE s.id = $2 AND s.revoked_at IS NULL AND s.expires_at > $8 AND s.idle_expires_at > $8
			FOR UPDATE OF s
			RETURNING id
		), tok AS (
			INSERT INTO refresh_tokens (token_hash, family_id, created_at, expires_at)
			SELECT $9, fam.id, $7, $10 FROM fam
			RETURNING token_hash
		)
		SELECT id FROM fam`,
		f.ID, f.SessionID, f.ClientID, f.UserID, strings.Join(f.Scope, " "), strings.Join(f.OIDCScopes, " "), f.CreatedAt, now,
		t.Hash, t.ExpiresAt, nullTime(f.AuthTime), nonNil(f.AuthMethods)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("insert refresh family: %w", err)
	}
	return true, nil
}

// LockSessionOfToken locks the session row of the family of a token. The
// session_id of a family never changes, so the read of it needs no lock.
func (r *RefreshTokens) LockSessionOfToken(ctx context.Context, tokenHash string) (string, bool, error) {
	var id string
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT id FROM sessions WHERE id = (
			SELECT session_id FROM refresh_token_families WHERE id = (
				SELECT family_id FROM refresh_tokens WHERE token_hash = $1))
		FOR UPDATE`, tokenHash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("lock session of token: %w", err)
	}
	return id, true, nil
}

// LockFamilyOfToken locks the family row of a token.
func (r *RefreshTokens) LockFamilyOfToken(ctx context.Context, tokenHash string) (domain.RefreshFamily, bool, error) {
	var (
		f           domain.RefreshFamily
		scope, oidc string
		authTime    *time.Time
	)
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT id, session_id, client_id, user_id, scope, oidc_scopes, created_at, revoked_at, auth_time, amr
		FROM refresh_token_families
		WHERE id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1)
		FOR UPDATE`, tokenHash).
		Scan(&f.ID, &f.SessionID, &f.ClientID, &f.UserID, &scope, &oidc, &f.CreatedAt, &f.RevokedAt, &authTime, &f.AuthMethods)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RefreshFamily{}, false, nil
	}
	if err != nil {
		return domain.RefreshFamily{}, false, fmt.Errorf("lock refresh family: %w", err)
	}
	f.Scope, f.OIDCScopes = strings.Fields(scope), strings.Fields(oidc)
	if authTime != nil {
		f.AuthTime = *authTime
	}
	return f, true, nil
}

// GetToken returns a token.
func (r *RefreshTokens) GetToken(ctx context.Context, tokenHash string) (domain.RefreshToken, error) {
	t := domain.RefreshToken{Hash: tokenHash}
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT family_id, created_at, used_at, expires_at FROM refresh_tokens WHERE token_hash = $1`, tokenHash).
		Scan(&t.FamilyID, &t.CreatedAt, &t.UsedAt, &t.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RefreshToken{}, fmt.Errorf("get refresh token: %w", refreshtokens.ErrNotFound)
	}
	if err != nil {
		return domain.RefreshToken{}, fmt.Errorf("get refresh token: %w", err)
	}
	return t, nil
}

// MarkUsed sets used_at of an unused token that has not expired.
func (r *RefreshTokens) MarkUsed(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE refresh_tokens SET used_at = $2 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2`, tokenHash, now)
	if err != nil {
		return false, fmt.Errorf("mark refresh token used: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// InsertToken adds a token.
func (r *RefreshTokens) InsertToken(ctx context.Context, t domain.RefreshToken) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO refresh_tokens (token_hash, family_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		t.Hash, t.FamilyID, t.CreatedAt, t.ExpiresAt); err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

// RevokeFamily revokes one family.
func (r *RefreshTokens) RevokeFamily(ctx context.Context, familyID string, now time.Time) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE refresh_token_families SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, familyID, now); err != nil {
		return fmt.Errorf("revoke refresh family: %w", err)
	}
	return nil
}

// RevokeSessionFamilies locks and revokes the families of a session.
func (r *RefreshTokens) RevokeSessionFamilies(ctx context.Context, sessionID string, now time.Time) error {
	return inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		// Lock the session row first. This is the lock order of all paths.
		if _, err := q.Exec(ctx, `SELECT id FROM sessions WHERE id = $1::uuid FOR UPDATE`, sessionID); err != nil {
			return fmt.Errorf("lock session: %w", err)
		}
		return revokeFamilies(ctx, q, `session_id = $1::uuid`, sessionID, now)
	})
}

// RevokeClientFamilies locks and revokes the families of a client.
func (r *RefreshTokens) RevokeClientFamilies(ctx context.Context, clientID string, now time.Time) error {
	return inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		// Lock the session rows first, in ascending ID order. This is the lock
		// order of all paths. Then lock the families.
		if _, err := q.Exec(ctx, `SELECT id FROM sessions WHERE id IN (
			SELECT session_id FROM refresh_token_families WHERE client_id = $1 AND revoked_at IS NULL)
			ORDER BY id FOR UPDATE`, clientID); err != nil {
			return fmt.Errorf("lock sessions of client: %w", err)
		}
		return revokeFamilies(ctx, q, `client_id = $1`, clientID, now)
	})
}

// RefreshState reads the client, the user, and the session of a family.
func (r *RefreshTokens) RefreshState(ctx context.Context, familyID string) (refreshtokens.State, error) {
	var st refreshtokens.State
	row := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT c.disabled, u.status = 'active',
		       s.id, s.user_id, s.token_hash, s.created_at, s.auth_time, s.amr, s.last_seen_at, s.idle_expires_at, s.expires_at, s.revoked_at, s.user_agent, s.ip_address
		FROM refresh_token_families f
		JOIN clients c ON c.id = f.client_id
		JOIN users u ON u.id = f.user_id
		JOIN sessions s ON s.id = f.session_id
		WHERE f.id = $1`, familyID)
	s := &st.Session
	err := row.Scan(&st.ClientDisabled, &st.UserActive,
		&s.ID, &s.UserID, &s.TokenHash, &s.CreatedAt, &s.AuthTime, &s.AuthMethods, &s.LastSeenAt, &s.IdleExpiresAt, &s.ExpiresAt, &s.RevokedAt, &s.UserAgent, &s.IPAddress)
	if errors.Is(err, pgx.ErrNoRows) {
		return refreshtokens.State{}, fmt.Errorf("refresh state: %w", refreshtokens.ErrNotFound)
	}
	if err != nil {
		return refreshtokens.State{}, fmt.Errorf("refresh state: %w", err)
	}
	return st, nil
}

// nullTime gives NULL for a zero time.
func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
