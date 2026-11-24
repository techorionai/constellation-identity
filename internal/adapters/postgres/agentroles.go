package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/agentroles"
)

// AgentRoles is the PostgreSQL repository of the role assignments of agents.
type AgentRoles struct {
	pool *pgxpool.Pool
}

var _ agentroles.Repository = (*AgentRoles)(nil)

// NewAgentRoles makes the repository.
func NewAgentRoles(pool *pgxpool.Pool) *AgentRoles { return &AgentRoles{pool: pool} }

// allRows is the limit of a query that must read all rows of one holder. An
// agent has a small number of roles.
const allRows = math.MaxInt32

// Get returns one assignment of an agent.
func (r *AgentRoles) Get(ctx context.Context, agentID string, role domain.RoleRef) (domain.RoleAssignment, bool, error) {
	var (
		a   domain.RoleAssignment
		src string
	)
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, `
		SELECT t.app, t.role, t.source, (ro.key IS NULL)
		FROM agent_roles t LEFT JOIN roles ro ON ro.app = t.app AND ro.key = t.role
		WHERE t.agent_id = $1 AND t.app = $2 AND t.role = $3`, agentID, role.App, role.Role).
		Scan(&a.Role.App, &a.Role.Role, &src, &a.Pending)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RoleAssignment{}, false, nil
	}
	if err != nil {
		return domain.RoleAssignment{}, false, fmt.Errorf("get agent role: %w", err)
	}
	a.Source = domain.AssignmentSource(src)
	return a, true, nil
}

// Assignments returns the assignments of an agent. The service calculates
// pending in this query. No column stores it.
func (r *AgentRoles) Assignments(ctx context.Context, agentID string) ([]domain.RoleAssignment, error) {
	return rolePage(ctx, clientspg.Conn(ctx, r.pool), `agent_roles`, `agent_id`, agentID, nil, allRows)
}

// Page returns a page of the assignments of an agent.
func (r *AgentRoles) Page(ctx context.Context, agentID string, after *domain.RoleRef, limit int) ([]domain.RoleAssignment, error) {
	return rolePage(ctx, clientspg.Conn(ctx, r.pool), `agent_roles`, `agent_id`, agentID, after, limit)
}

// GrantedPermissions returns the permissions of the roles that exist and that
// the agent has. The join to role_permissions drops a pending assignment,
// because a pending role has no row there.
func (r *AgentRoles) GrantedPermissions(ctx context.Context, agentID string) ([]string, error) {
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, `
		SELECT DISTINCT rp.permission
		FROM role_permissions rp
		WHERE EXISTS (SELECT 1 FROM agent_roles ar
		              WHERE ar.agent_id = $1 AND ar.app = rp.app AND ar.role = rp.role)
		ORDER BY rp.permission`, agentID)
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

// Assign gives a role to an agent.
func (r *AgentRoles) Assign(ctx context.Context, agentID string, role domain.RoleRef, source domain.AssignmentSource) error {
	if _, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO agent_roles (agent_id, app, role, source) VALUES ($1, $2, $3, $4)
		ON CONFLICT (agent_id, app, role) DO NOTHING`, agentID, role.App, role.Role, string(source)); err != nil {
		return fmt.Errorf("assign agent role %s: %w", role, err)
	}
	return nil
}

// Delete removes an assignment.
func (r *AgentRoles) Delete(ctx context.Context, agentID string, role domain.RoleRef) (bool, error) {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx,
		`DELETE FROM agent_roles WHERE agent_id = $1 AND app = $2 AND role = $3`, agentID, role.App, role.Role)
	if err != nil {
		return false, fmt.Errorf("delete agent role: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
