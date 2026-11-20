package domain

import (
	"errors"
	"strings"
)

// RoleRef is a reference to a role in the form <app>:<role>.
type RoleRef struct {
	App  string
	Role string
}

// ServiceRole is the implicit role of every service client.
var ServiceRole = RoleRef{App: IdentityApp, Role: "service"}

// String returns the form <app>:<role>.
func (r RoleRef) String() string { return r.App + ":" + r.Role }

// ErrInvalidRoleRef means a string is not a role reference.
var ErrInvalidRoleRef = errors.New("a role reference must have the form <app>:<role>")

// ParseRoleRef parses <app>:<role>.
func ParseRoleRef(s string) (RoleRef, error) {
	app, role, ok := strings.Cut(s, ":")
	if !ok || !ValidAppKey(app) || !ValidRoleKey(role) {
		return RoleRef{}, ErrInvalidRoleRef
	}
	return RoleRef{App: app, Role: role}, nil
}

// AssignmentSource tells where a role assignment comes from.
type AssignmentSource string

// The sources of a role assignment.
const (
	AssignmentConfig AssignmentSource = "config"
	AssignmentAPI    AssignmentSource = "api"
)

// RoleAssignment is a role that a client has. It is pending when the role is
// not in the current manifest of its app.
type RoleAssignment struct {
	Role    RoleRef
	Source  AssignmentSource
	Pending bool
}
