// Package clientroles is the port of the role assignments of clients.
package clientroles

import (
	"context"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Repository stores the role assignments of clients. The clients file writes
// the assignments with source config through the client repository.
type Repository interface {
	// Assignments returns the assignments of a client in order of app and
	// role. Pending is true when the role has no row in the current manifests.
	Assignments(ctx context.Context, clientID string) ([]domain.RoleAssignment, error)
	// Page returns up to limit assignments of a client in order of app and role,
	// after the role. A nil role means the start.
	Page(ctx context.Context, clientID string, after *domain.RoleRef, limit int) ([]domain.RoleAssignment, error)
	// GrantedPermissions returns the permission keys that the client has
	// through its assignments that are not pending, and through the implicit
	// roles. The result has no duplicates.
	GrantedPermissions(ctx context.Context, clientID string, implicit ...domain.RoleRef) ([]string, error)
	// Assign gives a role to a client. A second call does nothing.
	Assign(ctx context.Context, clientID string, role domain.RoleRef, source domain.AssignmentSource) error
	// Delete removes an assignment. It returns false if the client does not
	// have the role.
	Delete(ctx context.Context, clientID string, role domain.RoleRef) (bool, error)
}
