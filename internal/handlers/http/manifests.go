package httpapi

import (
	"context"

	"github.com/techorionai/constellation-platform-go/auth"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

// pageParams returns the page token and the page size of a list request.
func pageParams(token *string, size *int32) (string, int) {
	var t string
	var n int
	if token != nil {
		t = *token
	}
	if size != nil {
		n = int(*size)
	}
	return t, n
}

func optionalToken(token string) *string {
	if token == "" {
		return nil
	}
	return &token
}

func toDomainManifest(m gen.PermissionManifest) domain.Manifest {
	out := domain.Manifest{App: m.App}
	for _, p := range m.Permissions {
		out.Permissions = append(out.Permissions, domain.PermissionDef{Key: p.Key, Description: p.Description})
	}
	for _, r := range m.DefaultRoles {
		out.Roles = append(out.Roles, domain.RoleDef{
			Key: r.Key, Name: r.Name, Description: r.Description, Permissions: r.Permissions,
		})
	}
	return out
}

func toGenManifest(m domain.Manifest) gen.PermissionManifest {
	out := gen.PermissionManifest{
		App:          m.App,
		Permissions:  make([]gen.PermissionDefinition, 0, len(m.Permissions)),
		DefaultRoles: make([]gen.RoleDefinition, 0, len(m.Roles)),
	}
	for _, p := range m.Permissions {
		out.Permissions = append(out.Permissions, gen.PermissionDefinition{Key: p.Key, Description: p.Description})
	}
	for _, r := range m.Roles {
		perms := r.Permissions
		if perms == nil {
			perms = []string{}
		}
		out.DefaultRoles = append(out.DefaultRoles, gen.RoleDefinition{
			Key: r.Key, Name: r.Name, Description: r.Description, Permissions: perms,
		})
	}
	return out
}

func toGenPublished(p domain.PublishedManifest) gen.PublishedManifest {
	return gen.PublishedManifest{
		Manifest:    toGenManifest(p.Manifest),
		PublishedAt: p.PublishedAt,
		Version:     int32(p.Version), //nolint:gosec // The version stays far below the limit.
	}
}

func toGenRole(r domain.Role) gen.Role {
	perms := r.Permissions
	if perms == nil {
		perms = []string{}
	}
	return gen.Role{
		App: r.Ref.App, Key: r.Ref.Role, Ref: r.Ref.String(),
		Name: r.Name, Description: r.Description, Permissions: perms,
	}
}

// PermissionManifestsPublish publishes the manifest of the app of the caller.
func (s *Server) PermissionManifestsPublish(ctx context.Context, req gen.PermissionManifestsPublishRequestObject) (gen.PermissionManifestsPublishResponseObject, error) {
	p, _ := auth.PrincipalFromContext(ctx)
	var body gen.PermissionManifest
	if req.Body != nil {
		body = *req.Body
	}
	out, err := s.d.PublishManifest.Execute(ctx, commands.PublishManifest{
		PathApp:         req.App,
		CallerClientID:  p.ClientID,
		CallerIsService: p.Type == auth.PrincipalService,
		Manifest:        toDomainManifest(body),
		PublishedBy:     p.ID,
	})
	if err != nil {
		return nil, err
	}
	return gen.PermissionManifestsPublish200JSONResponse(toGenPublished(out)), nil
}

// PermissionManifestsList lists the manifests.
func (s *Server) PermissionManifestsList(ctx context.Context, req gen.PermissionManifestsListRequestObject) (gen.PermissionManifestsListResponseObject, error) {
	token, size := pageParams(req.Params.PageToken, req.Params.PageSize)
	res, err := s.d.ListManifests.Execute(ctx, queries.ListManifests{PageToken: token, PageSize: size})
	if err != nil {
		return nil, err
	}
	page := gen.PublishedManifestPage{Items: make([]gen.PublishedManifest, 0, len(res.Items))}
	for _, m := range res.Items {
		page.Items = append(page.Items, toGenPublished(m))
	}
	page.NextPageToken = optionalToken(res.NextPageToken)
	return gen.PermissionManifestsList200JSONResponse(page), nil
}

// PermissionManifestsGet reads the manifest of one app.
func (s *Server) PermissionManifestsGet(ctx context.Context, req gen.PermissionManifestsGetRequestObject) (gen.PermissionManifestsGetResponseObject, error) {
	m, err := s.d.GetManifest.Execute(ctx, queries.GetManifest{App: req.App})
	if err != nil {
		return nil, err
	}
	return gen.PermissionManifestsGet200JSONResponse(toGenPublished(m)), nil
}

// RolesList lists the roles.
func (s *Server) RolesList(ctx context.Context, req gen.RolesListRequestObject) (gen.RolesListResponseObject, error) {
	token, size := pageParams(req.Params.PageToken, req.Params.PageSize)
	var app string
	if req.Params.App != nil {
		app = *req.Params.App
	}
	res, err := s.d.ListRoles.Execute(ctx, queries.ListRoles{App: app, PageToken: token, PageSize: size})
	if err != nil {
		return nil, err
	}
	page := gen.RolePage{Items: make([]gen.Role, 0, len(res.Items))}
	for _, r := range res.Items {
		page.Items = append(page.Items, toGenRole(r))
	}
	page.NextPageToken = optionalToken(res.NextPageToken)
	return gen.RolesList200JSONResponse(page), nil
}

// RolesGet reads one role.
func (s *Server) RolesGet(ctx context.Context, req gen.RolesGetRequestObject) (gen.RolesGetResponseObject, error) {
	r, err := s.d.GetRole.Execute(ctx, queries.GetRole{Ref: req.Role})
	if err != nil {
		return nil, err
	}
	return gen.RolesGet200JSONResponse(toGenRole(r)), nil
}
