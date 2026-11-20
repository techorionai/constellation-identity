package queries

import (
	"context"
	"errors"
	"fmt"

	"github.com/techorionai/constellation-platform-go/executor"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
)

// ListRoles is the input of the role list. An empty App means all apps.
type ListRoles struct {
	App       string
	PageToken string
	PageSize  int
}

// ListRolesResult is one page of roles.
type ListRolesResult struct {
	Items         []domain.Role
	NextPageToken string
}

// ListRolesQuery lists roles in order of app and role.
type ListRolesQuery struct{ repo manifests.Repository }

var _ executor.ExecutorWithReturn[ListRoles, ListRolesResult] = (*ListRolesQuery)(nil)

// NewListRoles makes the query.
func NewListRoles(repo manifests.Repository) *ListRolesQuery { return &ListRolesQuery{repo: repo} }

// Execute returns one page.
func (q *ListRolesQuery) Execute(ctx context.Context, in ListRoles) (ListRolesResult, error) {
	size, err := pageSize(in.PageSize)
	if err != nil {
		return ListRolesResult{}, err
	}
	if in.App != "" && !domain.ValidAppKey(in.App) {
		return ListRolesResult{}, apperrors.NewInvalidInput("app is not valid")
	}
	cursor, err := decodePageToken(in.PageToken)
	if err != nil {
		return ListRolesResult{}, err
	}
	var after domain.RoleRef
	if cursor != "" {
		after, err = domain.ParseRoleRef(cursor)
		if err != nil {
			return ListRolesResult{}, apperrors.NewInvalidInput("pageToken is not valid")
		}
	}
	items, err := q.repo.Roles(ctx, in.App, after, size+1)
	if err != nil {
		return ListRolesResult{}, fmt.Errorf("list roles: %w", err)
	}
	res := ListRolesResult{Items: items}
	if len(items) > size {
		res.Items = items[:size]
		res.NextPageToken = encodePageToken(items[size-1].Ref.String())
	}
	return res, nil
}

// GetRole is the input of the role read. Ref has the form <app>:<role>.
type GetRole struct{ Ref string }

// GetRoleQuery reads one role.
type GetRoleQuery struct{ repo manifests.Repository }

var _ executor.ExecutorWithReturn[GetRole, domain.Role] = (*GetRoleQuery)(nil)

// NewGetRole makes the query.
func NewGetRole(repo manifests.Repository) *GetRoleQuery { return &GetRoleQuery{repo: repo} }

// Execute returns the role. A malformed reference is an invalid input. A role
// that does not exist is a NotFound error.
func (q *GetRoleQuery) Execute(ctx context.Context, in GetRole) (domain.Role, error) {
	ref, err := domain.ParseRoleRef(in.Ref)
	if err != nil {
		return domain.Role{}, apperrors.NewInvalidInput("role is not a role reference")
	}
	role, err := q.repo.Role(ctx, ref)
	if errors.Is(err, manifests.ErrNotFound) {
		return domain.Role{}, apperrors.NewNotFound("role not found")
	}
	if err != nil {
		return domain.Role{}, fmt.Errorf("get role: %w", err)
	}
	return role, nil
}
