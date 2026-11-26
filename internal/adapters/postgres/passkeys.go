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
	"github.com/techorionai/constellation-identity/internal/ports/passkeys"
)

// Passkeys is the PostgreSQL repository of the passkeys and the WebAuthn user
// handles.
type Passkeys struct {
	pool *pgxpool.Pool
}

var _ passkeys.Repository = (*Passkeys)(nil)

// NewPasskeys makes the repository.
func NewPasskeys(pool *pgxpool.Pool) *Passkeys { return &Passkeys{pool: pool} }

//nolint:gosec // G101: This is a list of columns, not a credential.
const passkeyColumns = `id, user_id, name, created_at, last_used_at, backup_state`

const credentialColumns = passkeyColumns + `, credential_id, public_key, sign_count, aaguid, transports, backup_eligible`

func scanPasskey(row pgx.Row) (domain.Passkey, error) {
	var p domain.Passkey
	err := row.Scan(&p.ID, &p.UserID, &p.Name, &p.CreatedAt, &p.LastUsedAt, &p.BackupState)
	return p, err
}

func scanCredential(row pgx.Row) (domain.PasskeyCredential, error) {
	var c domain.PasskeyCredential
	var count int64
	err := row.Scan(&c.ID, &c.UserID, &c.Name, &c.CreatedAt, &c.LastUsedAt, &c.BackupState,
		&c.CredentialID, &c.PublicKey, &count, &c.AAGUID, &c.Transports, &c.BackupEligible)
	if err == nil {
		if count < 0 || count > int64(^uint32(0)) {
			return domain.PasskeyCredential{}, fmt.Errorf("sign count %d is out of range", count)
		}
		c.SignCount = uint32(count)
	}
	return c, err
}

// List returns a page of the passkeys of a user.
func (r *Passkeys) List(ctx context.Context, userID string, after *domain.PageCursor, limit int) ([]domain.Passkey, error) {
	query := `SELECT ` + passkeyColumns + ` FROM webauthn_credentials WHERE user_id = $1`
	args := []any{userID}
	if after != nil {
		query += ` AND (created_at, id) > ($2, $3::uuid)`
		args = append(args, after.CreatedAt, after.ID)
	}
	query += ` ORDER BY created_at, id LIMIT ` + fmt.Sprint(limit)
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	defer rows.Close()
	var out []domain.Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan passkey: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	return out, nil
}

// Get returns one passkey of a user.
func (r *Passkeys) Get(ctx context.Context, userID, id string) (domain.Passkey, error) {
	p, err := scanPasskey(clientspg.Conn(ctx, r.pool).QueryRow(ctx,
		`SELECT `+passkeyColumns+` FROM webauthn_credentials WHERE id = $1 AND user_id = $2`, id, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Passkey{}, fmt.Errorf("get passkey: %w", passkeys.ErrNotFound)
	}
	if err != nil {
		return domain.Passkey{}, fmt.Errorf("get passkey: %w", err)
	}
	return p, nil
}

// Credentials returns all credentials of a user.
func (r *Passkeys) Credentials(ctx context.Context, userID string) ([]domain.PasskeyCredential, error) {
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx,
		`SELECT `+credentialColumns+` FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()
	var out []domain.PasskeyCredential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	return out, nil
}

// ByCredentialID returns the credential with a credential ID.
func (r *Passkeys) ByCredentialID(ctx context.Context, credentialID []byte) (domain.PasskeyCredential, error) {
	c, err := scanCredential(clientspg.Conn(ctx, r.pool).QueryRow(ctx,
		`SELECT `+credentialColumns+` FROM webauthn_credentials WHERE credential_id = $1`, credentialID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.PasskeyCredential{}, fmt.Errorf("get credential: %w", passkeys.ErrNotFound)
	}
	if err != nil {
		return domain.PasskeyCredential{}, fmt.Errorf("get credential: %w", err)
	}
	return c, nil
}

// Insert adds a credential. The user row is locked, so two parallel inserts of
// one user cannot pass the limit together.
func (r *Passkeys) Insert(ctx context.Context, c domain.PasskeyCredential, limit int) error {
	return inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		var one string
		if err := q.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, c.UserID).Scan(&one); err != nil {
			return fmt.Errorf("lock user: %w", err)
		}
		var n int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_id = $1`, c.UserID).Scan(&n); err != nil {
			return fmt.Errorf("count passkeys: %w", err)
		}
		if n >= limit {
			return fmt.Errorf("insert passkey: %w", passkeys.ErrLimit)
		}
		transports := c.Transports
		if transports == nil {
			transports = []string{}
		}
		if _, err := q.Exec(ctx, `
			INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, aaguid, transports,
				backup_eligible, backup_state, name, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			c.ID, c.UserID, c.CredentialID, c.PublicKey, int64(c.SignCount), nonNilBytes(c.AAGUID), transports,
			c.BackupEligible, c.BackupState, c.Name, c.CreatedAt); err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.Code == "23505" {
				return fmt.Errorf("insert passkey: %w", passkeys.ErrCredentialExists)
			}
			return fmt.Errorf("insert passkey: %w", err)
		}
		return nil
	})
}

func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// Rename sets the name of a passkey and returns the old name.
func (r *Passkeys) Rename(ctx context.Context, userID, id, name string) (string, error) {
	var old string
	err := inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		err := q.QueryRow(ctx, `SELECT name FROM webauthn_credentials WHERE id = $1 AND user_id = $2 FOR UPDATE`, id, userID).Scan(&old)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("rename passkey: %w", passkeys.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("rename passkey: %w", err)
		}
		if _, err := q.Exec(ctx, `UPDATE webauthn_credentials SET name = $3 WHERE id = $1 AND user_id = $2`, id, userID, name); err != nil {
			return fmt.Errorf("rename passkey: %w", err)
		}
		return nil
	})
	return old, err
}

// Remove deletes a passkey of a user.
func (r *Passkeys) Remove(ctx context.Context, userID, id string) error {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return fmt.Errorf("remove passkey: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("remove passkey: %w", passkeys.ErrNotFound)
	}
	return nil
}

// RemoveAll deletes all passkeys of a user.
func (r *Passkeys) RemoveAll(ctx context.Context, userID string) (int, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `DELETE FROM webauthn_credentials WHERE user_id = $1`, userID)
	if err != nil {
		return 0, fmt.Errorf("remove passkeys: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// Count returns the number of passkeys of a user.
func (r *Passkeys) Count(ctx context.Context, userID string) (int, error) {
	var n int
	if err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_id = $1`, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count passkeys: %w", err)
	}
	return n, nil
}

// AdvanceSignCount stores a new sign count in one conditional statement. It is
// the rule of domain.SignCountAccepted. If no row changes, a parallel request
// used the credential first, or the count is not larger.
func (r *Passkeys) AdvanceSignCount(ctx context.Context, id string, next uint32, backupState bool, now time.Time) (bool, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		UPDATE webauthn_credentials SET sign_count = $2, backup_state = $3, last_used_at = $4
		WHERE id = $1 AND (sign_count < $2 OR (sign_count = 0 AND $2 = 0))`, id, int64(next), backupState, now)
	if err != nil {
		return false, fmt.Errorf("advance sign count: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// EnsureUserHandle returns the WebAuthn user handle of a user, and stores the
// candidate if the user has none.
func (r *Passkeys) EnsureUserHandle(ctx context.Context, userID string, candidate []byte) ([]byte, error) {
	q := clientspg.Conn(ctx, r.pool)
	if _, err := q.Exec(ctx, `UPDATE users SET webauthn_user_handle = $2 WHERE id = $1 AND webauthn_user_handle IS NULL`, userID, candidate); err != nil {
		return nil, fmt.Errorf("store user handle: %w", err)
	}
	var h []byte
	err := q.QueryRow(ctx, `SELECT webauthn_user_handle FROM users WHERE id = $1`, userID).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && h == nil) {
		return nil, fmt.Errorf("get user handle: %w", passkeys.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get user handle: %w", err)
	}
	return h, nil
}

// UserIDByHandle returns the ID of the user with a WebAuthn user handle.
func (r *Passkeys) UserIDByHandle(ctx context.Context, handle []byte) (string, error) {
	var id string
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `SELECT id FROM users WHERE webauthn_user_handle = $1`, handle).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("find user by handle: %w", passkeys.ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("find user by handle: %w", err)
	}
	return id, nil
}
