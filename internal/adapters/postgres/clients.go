package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
)

// Clients is the PostgreSQL repository of the OAuth clients.
type Clients struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

var _ clients.Repository = (*Clients)(nil)

// NewClients makes the repository.
func NewClients(pool *pgxpool.Pool) *Clients { return &Clients{pool: pool, now: time.Now} }

// UpsertConfig adds or updates a client of the clients file and replaces its
// keys and redirect URIs, in one transaction. If the context has a transaction,
// the work is a savepoint in it, so the caller can write an audit entry in the
// same transaction.
func (r *Clients) UpsertConfig(ctx context.Context, c domain.ClientConfig) (bool, error) {
	now := r.now().UTC()
	var (
		tx  pgx.Tx
		err error
	)
	if outer, ok := clientspg.TxFromContext(ctx); ok {
		tx, err = outer.Begin(ctx)
	} else {
		tx, err = r.pool.Begin(ctx)
	}
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		INSERT INTO clients (id, type, app, name, disabled, source, created_at, updated_at)
		VALUES ($1, $2, $3, $4, false, 'config', $5, $5)
		ON CONFLICT (id) DO UPDATE
		SET type = EXCLUDED.type, app = EXCLUDED.app, name = EXCLUDED.name,
		    disabled = false, updated_at = EXCLUDED.updated_at
		WHERE clients.source = 'config'`,
		c.Client.ID, string(c.Client.Type), c.Client.App, c.Client.Name, now)
	if err != nil {
		return false, fmt.Errorf("upsert client %s: %w", c.Client.ID, err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}

	kids := make([]string, 0, len(c.Keys))
	for _, k := range c.Keys {
		jwk, err := json.Marshal(k.PublicJWK)
		if err != nil {
			return false, fmt.Errorf("encode key %s: %w", k.KID, err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO client_keys (client_id, kid, public_jwk, created_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (client_id, kid) DO UPDATE SET public_jwk = EXCLUDED.public_jwk`,
			c.Client.ID, k.KID, jwk, now); err != nil {
			return false, fmt.Errorf("upsert key %s: %w", k.KID, err)
		}
		kids = append(kids, k.KID)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM client_keys WHERE client_id = $1 AND NOT (kid = ANY($2))`,
		c.Client.ID, kids); err != nil {
		return false, fmt.Errorf("delete old keys of %s: %w", c.Client.ID, err)
	}
	if err := replaceRedirectURIs(ctx, tx, c.Client); err != nil {
		return false, err
	}
	// Replace the assignments of the file. An assignment with source api stays.
	if _, err := tx.Exec(ctx,
		`DELETE FROM client_roles WHERE client_id = $1 AND source = 'config'`, c.Client.ID); err != nil {
		return false, fmt.Errorf("delete old roles of %s: %w", c.Client.ID, err)
	}
	for _, ref := range c.Roles {
		if _, err := tx.Exec(ctx, `
			INSERT INTO client_roles (client_id, app, role, source) VALUES ($1, $2, $3, 'config')
			ON CONFLICT (client_id, app, role) DO NOTHING`, c.Client.ID, ref.App, ref.Role); err != nil {
			return false, fmt.Errorf("insert role %s of %s: %w", ref, c.Client.ID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}

// replaceRedirectURIs writes the redirect URIs of a client. It replaces the
// old rows.
func replaceRedirectURIs(ctx context.Context, q clientspg.Querier, c domain.Client) error {
	if _, err := q.Exec(ctx, `DELETE FROM client_redirect_uris WHERE client_id = $1`, c.ID); err != nil {
		return fmt.Errorf("delete redirect URIs of %s: %w", c.ID, err)
	}
	for kind, uris := range map[domain.RedirectKind][]string{
		domain.RedirectLogin: c.RedirectURIs, domain.RedirectPostLogout: c.PostLogoutRedirectURIs,
	} {
		for _, u := range uris {
			if _, err := q.Exec(ctx, `
				INSERT INTO client_redirect_uris (client_id, uri, kind) VALUES ($1, $2, $3)
				ON CONFLICT DO NOTHING`, c.ID, u, string(kind)); err != nil {
				return fmt.Errorf("insert redirect URI of %s: %w", c.ID, err)
			}
		}
	}
	return nil
}

// DisableConfigNotIn disables each config client that is not in ids.
func (r *Clients) DisableConfigNotIn(ctx context.Context, ids []string) ([]string, error) {
	if ids == nil {
		ids = []string{}
	}
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, `
		UPDATE clients SET disabled = true, updated_at = $2
		WHERE source = 'config' AND NOT disabled AND NOT (id = ANY($1))
		RETURNING id`, ids, r.now().UTC())
	if err != nil {
		return nil, fmt.Errorf("disable clients: %w", err)
	}
	defer rows.Close()
	var changed []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan client id: %w", err)
		}
		changed = append(changed, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("disable clients: %w", err)
	}
	return changed, nil
}

const clientColumns = `id, type, app, name, disabled, source, created_at, updated_at`

func scanClient(row pgx.Row) (domain.Client, error) {
	var (
		c        domain.Client
		typ, src string
	)
	err := row.Scan(&c.ID, &typ, &c.App, &c.Name, &c.Disabled, &src, &c.CreatedAt, &c.UpdatedAt)
	c.Type = domain.ClientType(typ)
	c.Source = domain.ClientSource(src)
	return c, err
}

// Get returns a client with its redirect URIs.
func (r *Clients) Get(ctx context.Context, id string) (domain.Client, error) {
	c, err := scanClient(clientspg.Conn(ctx, r.pool).QueryRow(ctx, `SELECT `+clientColumns+` FROM clients WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Client{}, fmt.Errorf("client %s: %w", id, clients.ErrNotFound)
	}
	if err != nil {
		return domain.Client{}, fmt.Errorf("get client: %w", err)
	}
	if err := r.loadURIs(ctx, &c); err != nil {
		return domain.Client{}, err
	}
	return c, nil
}

// LockByID returns a client and locks its row.
func (r *Clients) LockByID(ctx context.Context, id string) (domain.Client, error) {
	c, err := scanClient(clientspg.Conn(ctx, r.pool).QueryRow(ctx, `SELECT `+clientColumns+` FROM clients WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Client{}, fmt.Errorf("client %s: %w", id, clients.ErrNotFound)
	}
	if err != nil {
		return domain.Client{}, fmt.Errorf("lock client: %w", err)
	}
	if err := r.loadURIs(ctx, &c); err != nil {
		return domain.Client{}, err
	}
	return c, nil
}

func (r *Clients) loadURIs(ctx context.Context, c *domain.Client) error {
	if c.Type != domain.ClientTypePublic {
		return nil
	}
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx,
		`SELECT uri, kind FROM client_redirect_uris WHERE client_id = $1 ORDER BY kind, uri`, c.ID)
	if err != nil {
		return fmt.Errorf("list redirect URIs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var uri, kind string
		if err := rows.Scan(&uri, &kind); err != nil {
			return fmt.Errorf("scan redirect URI: %w", err)
		}
		if domain.RedirectKind(kind) == domain.RedirectLogin {
			c.RedirectURIs = append(c.RedirectURIs, uri)
		} else {
			c.PostLogoutRedirectURIs = append(c.PostLogoutRedirectURIs, uri)
		}
	}
	return rows.Err()
}

// Keys returns the public keys of a client.
func (r *Clients) Keys(ctx context.Context, id string) ([]domain.ClientKey, error) {
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, `
		SELECT client_id, kid, public_jwk, created_at
		FROM client_keys WHERE client_id = $1 ORDER BY kid`, id)
	if err != nil {
		return nil, fmt.Errorf("list client keys: %w", err)
	}
	defer rows.Close()
	var keys []domain.ClientKey
	for rows.Next() {
		var (
			k   domain.ClientKey
			jwk []byte
		)
		if err := rows.Scan(&k.ClientID, &k.KID, &jwk, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan client key: %w", err)
		}
		if err := json.Unmarshal(jwk, &k.PublicJWK); err != nil {
			return nil, fmt.Errorf("decode client key %s: %w", k.KID, err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list client keys: %w", err)
	}
	return keys, nil
}

// Create adds a client with the source api.
func (r *Clients) Create(ctx context.Context, c domain.Client, key *domain.ClientKey) error {
	return inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO clients (id, type, app, name, disabled, source, created_at, updated_at)
			VALUES ($1, $2, $3, $4, false, 'api', $5, $5)`,
			c.ID, string(c.Type), c.App, c.Name, c.CreatedAt)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return clients.ErrExists
		}
		if err != nil {
			return fmt.Errorf("create client: %w", err)
		}
		if err := replaceRedirectURIs(ctx, q, c); err != nil {
			return err
		}
		if key != nil {
			jwk, err := json.Marshal(key.PublicJWK)
			if err != nil {
				return fmt.Errorf("encode key: %w", err)
			}
			if _, err := q.Exec(ctx, `INSERT INTO client_keys (client_id, kid, public_jwk, created_at) VALUES ($1, $2, $3, $4)`,
				c.ID, key.KID, jwk, c.CreatedAt); err != nil {
				return fmt.Errorf("insert key: %w", err)
			}
		}
		return nil
	})
}

// Update writes the name, the disabled flag, and the redirect URIs.
func (r *Clients) Update(ctx context.Context, c domain.Client) error {
	return inTx(ctx, r.pool, func(ctx context.Context, q clientspg.Querier) error {
		tag, err := q.Exec(ctx, `UPDATE clients SET name = $2, disabled = $3, updated_at = $4 WHERE id = $1`,
			c.ID, c.Name, c.Disabled, r.now().UTC())
		if err != nil {
			return fmt.Errorf("update client: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("client %s: %w", c.ID, clients.ErrNotFound)
		}
		if c.Type == domain.ClientTypePublic {
			return replaceRedirectURIs(ctx, q, c)
		}
		return nil
	})
}

// List returns a page of clients.
func (r *Clients) List(ctx context.Context, after *domain.PageCursor, limit int) ([]domain.Client, error) {
	query := `SELECT ` + clientColumns + ` FROM clients`
	var args []any
	if after != nil {
		query += ` WHERE (created_at, id) > ($1, $2)`
		args = append(args, after.CreatedAt, after.ID)
	}
	query += ` ORDER BY created_at, id LIMIT ` + fmt.Sprint(limit)
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	var out []domain.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan client: %w", err)
		}
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	for i := range out {
		if err := r.loadURIs(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// AddKey adds a key to a client.
func (r *Clients) AddKey(ctx context.Context, k domain.ClientKey) error {
	jwk, err := json.Marshal(k.PublicJWK)
	if err != nil {
		return fmt.Errorf("encode key: %w", err)
	}
	_, err = clientspg.Conn(ctx, r.pool).Exec(ctx,
		`INSERT INTO client_keys (client_id, kid, public_jwk, created_at) VALUES ($1, $2, $3, $4)`,
		k.ClientID, k.KID, jwk, k.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return clients.ErrKeyExists
	}
	if err != nil {
		return fmt.Errorf("add key: %w", err)
	}
	return nil
}

// DeleteKey removes a key.
func (r *Clients) DeleteKey(ctx context.Context, clientID, kid string) (bool, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `DELETE FROM client_keys WHERE client_id = $1 AND kid = $2`, clientID, kid)
	if err != nil {
		return false, fmt.Errorf("delete key: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// LoginRedirectURIs returns the login redirect URIs of the public clients that
// are not disabled.
func (r *Clients) LoginRedirectURIs(ctx context.Context) ([]string, error) {
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, `
		SELECT u.uri FROM client_redirect_uris u JOIN clients c ON c.id = u.client_id
		WHERE u.kind = 'login' AND c.type = 'public' AND NOT c.disabled`)
	if err != nil {
		return nil, fmt.Errorf("list login redirect URIs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, fmt.Errorf("scan redirect URI: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// WithLock runs fn while this instance holds the advisory lock of the clients
// sync.
func (r *Clients) WithLock(ctx context.Context, fn func(ctx context.Context) error) error {
	return withAdvisoryLock(ctx, r.pool, clientsSyncLock, fn)
}
