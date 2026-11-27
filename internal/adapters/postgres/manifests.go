package postgres

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
)

// Manifests is the PostgreSQL repository of the manifests, the permissions,
// and the roles.
type Manifests struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

var _ manifests.Repository = (*Manifests)(nil)

// NewManifests makes the repository.
func NewManifests(pool *pgxpool.Pool) *Manifests { return &Manifests{pool: pool, now: time.Now} }

// querier is the read part of a pool and of a transaction.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Publish stores a manifest in one transaction. The transaction inserts the
// apps row if it does not exist, then locks it. A second publish of the same
// app waits for the lock and sees the result of the first one.
func (r *Manifests) Publish(ctx context.Context, m domain.Manifest, publishedBy string) (domain.PublishedManifest, error) {
	hash := m.Hash()
	now := r.now().UTC()
	// With a transaction in the context, the work is a savepoint in it, so the
	// caller can write the audit entry in the same transaction.
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
		return domain.PublishedManifest{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// A row with version 0 is a placeholder. It is visible only in this
	// transaction, because the transaction either replaces it or rolls back.
	if _, err := tx.Exec(ctx, `
		INSERT INTO apps (key, manifest_version, manifest_hash, published_at, published_by)
		VALUES ($1, 0, '', $2, $3) ON CONFLICT (key) DO NOTHING`, m.App, now, publishedBy); err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("insert app: %w", err)
	}
	var (
		version int
		stored  string
	)
	if err := tx.QueryRow(ctx,
		`SELECT manifest_version, manifest_hash FROM apps WHERE key = $1 FOR UPDATE`, m.App).
		Scan(&version, &stored); err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("lock app: %w", err)
	}
	if version > 0 && stored == hash {
		return loadManifest(ctx, tx, m.App)
	}

	// Replace the permissions and the roles. The foreign keys delete the role
	// permissions. No statement touches client_roles.
	for _, q := range []string{`DELETE FROM roles WHERE app = $1`, `DELETE FROM permissions WHERE app = $1`} {
		if _, err := tx.Exec(ctx, q, m.App); err != nil {
			return domain.PublishedManifest{}, fmt.Errorf("delete old manifest: %w", err)
		}
	}
	if err := insertManifestRows(ctx, tx, m); err != nil {
		return domain.PublishedManifest{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE apps SET manifest_version = manifest_version + 1, manifest_hash = $2,
		                published_at = $3, published_by = $4
		WHERE key = $1`, m.App, hash, now, publishedBy); err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("update app: %w", err)
	}
	out, err := loadManifest(ctx, tx, m.App)
	if err != nil {
		return domain.PublishedManifest{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("commit: %w", err)
	}
	out.Changed = true
	return out, nil
}

// insertBatch is the largest number of rows in one insert statement.
const insertBatch = 1000

// insertManifestRows inserts the permissions, the roles, and the role
// permissions of a manifest. Each statement inserts a batch of rows from
// unnest arrays, so the number of statements is small.
func insertManifestRows(ctx context.Context, tx pgx.Tx, m domain.Manifest) error {
	for chunk := range slices.Chunk(m.Permissions, insertBatch) {
		keys := make([]string, len(chunk))
		descriptions := make([]string, len(chunk))
		for i, p := range chunk {
			keys[i], descriptions[i] = p.Key, p.Description
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO permissions (key, app, description)
			SELECT k, $1, d FROM unnest($2::text[], $3::text[]) AS t (k, d)`,
			m.App, keys, descriptions); err != nil {
			return fmt.Errorf("insert permissions: %w", err)
		}
	}
	for chunk := range slices.Chunk(m.Roles, insertBatch) {
		keys := make([]string, len(chunk))
		names := make([]string, len(chunk))
		descriptions := make([]string, len(chunk))
		for i, r := range chunk {
			keys[i], names[i], descriptions[i] = r.Key, r.Name, r.Description
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO roles (app, key, name, description)
			SELECT $1, k, n, d FROM unnest($2::text[], $3::text[], $4::text[]) AS t (k, n, d)`,
			m.App, keys, names, descriptions); err != nil {
			return fmt.Errorf("insert roles: %w", err)
		}
	}
	type rolePermission struct{ role, permission string }
	var pairs []rolePermission
	for _, r := range m.Roles {
		for _, p := range r.Permissions {
			pairs = append(pairs, rolePermission{role: r.Key, permission: p})
		}
	}
	for chunk := range slices.Chunk(pairs, insertBatch) {
		roles := make([]string, len(chunk))
		permissions := make([]string, len(chunk))
		for i, p := range chunk {
			roles[i], permissions[i] = p.role, p.permission
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_permissions (app, role, permission)
			SELECT $1, r, p FROM unnest($2::text[], $3::text[]) AS t (r, p)`,
			m.App, roles, permissions); err != nil {
			return fmt.Errorf("insert role permissions: %w", err)
		}
	}
	return nil
}

// loadManifest reads the manifest of an app.
func loadManifest(ctx context.Context, q querier, app string) (domain.PublishedManifest, error) {
	out, err := loadManifests(ctx, q, []string{app})
	if err != nil {
		return domain.PublishedManifest{}, err
	}
	if len(out) == 0 {
		return domain.PublishedManifest{}, fmt.Errorf("manifest of app %s: %w", app, manifests.ErrNotFound)
	}
	return out[0], nil
}

// loadManifests reads the manifests of some apps with 3 queries, for any
// number of apps. An app with no published manifest is not in the result. The
// result is in order of the app key.
func loadManifests(ctx context.Context, q querier, apps []string) ([]domain.PublishedManifest, error) {
	rows, err := q.Query(ctx, `
		SELECT key, manifest_version, manifest_hash, published_at, published_by
		FROM apps WHERE key = ANY($1) AND manifest_version > 0 ORDER BY key`, apps)
	if err != nil {
		return nil, fmt.Errorf("get apps: %w", err)
	}
	var out []domain.PublishedManifest
	index := make(map[string]int, len(apps))
	for rows.Next() {
		var m domain.PublishedManifest
		if err := rows.Scan(&m.Manifest.App, &m.Version, &m.Hash, &m.PublishedAt, &m.PublishedBy); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan app: %w", err)
		}
		index[m.Manifest.App] = len(out)
		out = append(out, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("get apps: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}

	rows, err = q.Query(ctx, `
		SELECT app, key, description FROM permissions WHERE app = ANY($1) ORDER BY app, key`, apps)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	for rows.Next() {
		var (
			app string
			p   domain.PermissionDef
		)
		if err := rows.Scan(&app, &p.Key, &p.Description); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		if i, ok := index[app]; ok {
			out[i].Manifest.Permissions = append(out[i].Manifest.Permissions, p)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}

	roles, err := queryRoles(ctx, q, `WHERE r.app = ANY($1)`, 0, apps)
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		if i, ok := index[role.Ref.App]; ok {
			out[i].Manifest.Roles = append(out[i].Manifest.Roles, domain.RoleDef{
				Key: role.Ref.Role, Name: role.Name, Description: role.Description, Permissions: role.Permissions,
			})
		}
	}
	return out, nil
}

// queryRoles reads roles with their permissions. where is a condition with
// the alias r, limit is the largest number of roles (0 means no limit), and
// args are the arguments of the condition. The result is in order of app and
// role.
func queryRoles(ctx context.Context, q querier, where string, limit int, args ...any) ([]domain.Role, error) {
	suffix := ""
	if limit > 0 {
		suffix = fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := q.Query(ctx, `
		SELECT r.app, r.key, r.name, r.description,
		       COALESCE(array_agg(rp.permission ORDER BY rp.permission)
		                FILTER (WHERE rp.permission IS NOT NULL), '{}')
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.app = r.app AND rp.role = r.key `+where+`
		GROUP BY r.app, r.key, r.name, r.description
		ORDER BY r.app, r.key`+suffix, args...)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()
	var out []domain.Role
	for rows.Next() {
		var role domain.Role
		if err := rows.Scan(&role.Ref.App, &role.Ref.Role, &role.Name, &role.Description, &role.Permissions); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return out, nil
}

// Get returns the manifest of an app.
func (r *Manifests) Get(ctx context.Context, app string) (domain.PublishedManifest, error) {
	return loadManifest(ctx, r.pool, app)
}

// List returns manifests in app order.
func (r *Manifests) List(ctx context.Context, afterApp string, limit int) ([]domain.PublishedManifest, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT key FROM apps WHERE manifest_version > 0 AND key > $1 ORDER BY key LIMIT $2`, afterApp, limit)
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	var apps []string
	for rows.Next() {
		var app string
		if err := rows.Scan(&app); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan app: %w", err)
		}
		apps = append(apps, app)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	if len(apps) == 0 {
		return []domain.PublishedManifest{}, nil
	}
	return loadManifests(ctx, r.pool, apps)
}

// HasManifest reports whether the app has a published manifest.
func (r *Manifests) HasManifest(ctx context.Context, app string) (bool, error) {
	var ok bool
	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM apps WHERE key = $1 AND manifest_version > 0)`, app).Scan(&ok); err != nil {
		return false, fmt.Errorf("check manifest: %w", err)
	}
	return ok, nil
}

// Role returns a role.
func (r *Manifests) Role(ctx context.Context, ref domain.RoleRef) (domain.Role, error) {
	roles, err := queryRoles(ctx, r.pool, `WHERE r.app = $1 AND r.key = $2`, 1, ref.App, ref.Role)
	if err != nil {
		return domain.Role{}, err
	}
	if len(roles) == 0 {
		return domain.Role{}, fmt.Errorf("role %s: %w", ref, manifests.ErrNotFound)
	}
	return roles[0], nil
}

// Roles returns roles after a reference.
func (r *Manifests) Roles(ctx context.Context, app string, after domain.RoleRef, limit int) ([]domain.Role, error) {
	return queryRoles(ctx, r.pool, `
		WHERE ($1 = '' OR r.app = $1) AND (r.app, r.key) > ($2, $3)`, limit, app, after.App, after.Role)
}
