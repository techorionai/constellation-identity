// Package agentroles is the port of the role assignments of agents.
package agentroles

import (
	"context"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Repository stores the role assignments of agents.
type Repository interface {
	// Assignments returns the assignments of an agent in order of app and
	// role. Pending is true when the role has no row in the current manifests.
	Assignments(ctx context.Context, agentID string) ([]domain.RoleAssignment, error)
	// Page returns up to limit assignments of an agent in order of app and
	// role, after the role. A nil role means the start.
	Page(ctx context.Context, agentID string, after *domain.RoleRef, limit int) ([]domain.RoleAssignment, error)
	// GrantedPermissions returns the permission keys that the agent has through
	// assignments that are not pending. The result has no duplicates.
	GrantedPermissions(ctx context.Context, agentID string) ([]string, error)
	// Assign gives a role to an agent. A second call does nothing.
	Assign(ctx context.Context, agentID string, role domain.RoleRef, source domain.AssignmentSource) error
	// Delete removes an assignment. It returns false if the agent does not
	// have the role.
	Delete(ctx context.Context, agentID string, role domain.RoleRef) (bool, error)
}
