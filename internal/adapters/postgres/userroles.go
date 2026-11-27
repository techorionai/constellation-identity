package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/userroles"
)

// UserRoles is the PostgreSQL repository of the role assignments of users.
type UserRoles struct {
	pool *pgxpool.Pool
}

var _ userroles.Repository = (*UserRoles)(nil)

// NewUserRoles makes the repository.
func NewUserRoles(pool *pgxpool.Pool) *UserRoles { return &UserRoles{pool: pool} }

// Assign gives a role to a user. It returns true if it added a row, and false
// if the user had the role.
func (r *UserRoles) Assign(ctx context.Context, userID string, role domain.RoleRef, source domain.AssignmentSource) (bool, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO user_roles (user_id, app, role, source) VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, app, role) DO NOTHING`,
		userID, role.App, role.Role, string(source))
	if err != nil {
		return false, fmt.Errorf("assign role %s: %w", role, err)
	}
	return tag.RowsAffected() == 1, nil
}

// Assignments returns the assignments of a user. Pending is calculated in this
// query. No column stores it.
func (r *UserRoles) Assignments(ctx context.Context, userID string) ([]domain.RoleAssignment, error) {
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, `
		SELECT ur.app, ur.role, ur.source, (ro.key IS NULL)
		FROM user_roles ur
		LEFT JOIN roles ro ON ro.app = ur.app AND ro.key = ur.role
		WHERE ur.user_id = $1
		ORDER BY ur.app, ur.role`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	defer rows.Close()
	var out []domain.RoleAssignment
	for rows.Next() {
		var (
			a   domain.RoleAssignment
			src string
		)
		if err := rows.Scan(&a.Role.App, &a.Role.Role, &src, &a.Pending); err != nil {
			return nil, fmt.Errorf("scan user role: %w", err)
		}
		a.Source = domain.AssignmentSource(src)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	return out, nil
}

// ActiveUserHasRole reports whether an active user has the role.
func (r *UserRoles) ActiveUserHasRole(ctx context.Context, role domain.RoleRef) (bool, error) {
	var ok bool
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM user_roles ur JOIN users u ON u.id = ur.user_id
			WHERE ur.app = $1 AND ur.role = $2 AND u.status = 'active')`,
		role.App, role.Role).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check role holders: %w", err)
	}
	return ok, nil
}

// Delete removes an assignment.
func (r *UserRoles) Delete(ctx context.Context, userID string, role domain.RoleRef) (bool, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx,
		`DELETE FROM user_roles WHERE user_id = $1 AND app = $2 AND role = $3`, userID, role.App, role.Role)
	if err != nil {
		return false, fmt.Errorf("delete user role: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Page returns a page of the assignments of a user. The query compares the row
// (app, role) with the cursor.
func (r *UserRoles) Page(ctx context.Context, userID string, after *domain.RoleRef, limit int) ([]domain.RoleAssignment, error) {
	return rolePage(ctx, clientspg.Conn(ctx, r.pool), `user_roles`, `user_id`, userID, after, limit)
}

// GrantedPermissions returns the permissions of the roles that exist and that
// the user has, and of the implicit roles. The join to role_permissions drops a
// pending assignment, because a pending role has no row there.
func (r *UserRoles) GrantedPermissions(ctx context.Context, userID string, implicit ...domain.RoleRef) ([]string, error) {
	apps := make([]string, 0, len(implicit))
	roles := make([]string, 0, len(implicit))
	for _, ref := range implicit {
		apps = append(apps, ref.App)
		roles = append(roles, ref.Role)
	}
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, `
		SELECT DISTINCT rp.permission
		FROM role_permissions rp
		WHERE EXISTS (SELECT 1 FROM user_roles ur
		              WHERE ur.user_id = $1 AND ur.app = rp.app AND ur.role = rp.role)
		   OR EXISTS (SELECT 1 FROM unnest($2::text[], $3::text[]) AS i (app, role)
		              WHERE i.app = rp.app AND i.role = rp.role)
		ORDER BY rp.permission`, userID, apps, roles)
	if err != nil {
		return nil, fmt.Errorf("list granted permissions: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list granted permissions: %w", err)
	}
	return out, nil
}

// CountActiveHolders counts the active users that have a role that is not
// pending and that grants the permission.
func (r *UserRoles) CountActiveHolders(ctx context.Context, permission string) (int, error) {
	var n int
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT count(DISTINCT u.id)
		FROM users u
		JOIN user_roles ur ON ur.user_id = u.id
		JOIN role_permissions rp ON rp.app = ur.app AND rp.role = ur.role
		WHERE u.status = 'active' AND rp.permission = $1`, permission).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count permission holders: %w", err)
	}
	return n, nil
}

// rolePage reads a page of the role assignments of a holder. The table and
// the column are constants of the caller.
func rolePage(ctx context.Context, q clientspg.Querier, table, col, holder string, after *domain.RoleRef, limit int) ([]domain.RoleAssignment, error) {
	query := `SELECT t.app, t.role, t.source, (ro.key IS NULL)
		FROM ` + table + ` t LEFT JOIN roles ro ON ro.app = t.app AND ro.key = t.role
		WHERE t.` + col + ` = $1`
	args := []any{holder}
	if after != nil {
		query += ` AND (t.app, t.role) > ($2, $3)`
		args = append(args, after.App, after.Role)
	}
	query += ` ORDER BY t.app, t.role LIMIT ` + fmt.Sprint(limit)
	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()
	var out []domain.RoleAssignment
	for rows.Next() {
		var (
			a   domain.RoleAssignment
			src string
		)
		if err := rows.Scan(&a.Role.App, &a.Role.Role, &src, &a.Pending); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		a.Source = domain.AssignmentSource(src)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return out, nil
}
