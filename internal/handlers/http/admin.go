package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/techorionai/constellation-platform-go/auth"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

func actorID(ctx context.Context) string {
	p, _ := auth.PrincipalFromContext(ctx)
	return p.ID
}

func listPage(size *int32, token *string) commands.ListPage {
	p := commands.ListPage{Size: size}
	if token != nil {
		p.Token = *token
	}
	return p
}

func nextToken(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func parseRole(r gen.RoleRef) (domain.RoleRef, error) {
	ref, err := domain.ParseRoleRef(r)
	if err != nil {
		return domain.RoleRef{}, apperrors.NewInvalidInput("the role is not a role reference")
	}
	return ref, nil
}

// --- conversions ---

func genUser(u domain.User) gen.User {
	return gen.User{CreatedAt: u.CreatedAt, Email: u.Email, Id: u.ID, Name: u.Name, Status: gen.UserStatus(u.Status)}
}

func genJWK(k domain.PublicJWK) gen.JsonWebKey {
	j := gen.JsonWebKey{
		Crv: gen.JsonWebKeyCrv(k.Crv), Kid: k.Kid, Kty: gen.JsonWebKeyKty(k.Kty), X: k.X, Y: k.Y,
	}
	if k.Use != "" {
		u := gen.JsonWebKeyUse(k.Use)
		j.Use = &u
	}
	if k.Alg != "" {
		a := gen.JsonWebKeyAlg(k.Alg)
		j.Alg = &a
	}
	return j
}

func genClientKey(k domain.ClientKey) gen.ClientKey {
	return gen.ClientKey{CreatedAt: k.CreatedAt, Jwk: genJWK(k.PublicJWK), Kid: k.KID}
}

func genClient(v commands.ClientView) gen.Client {
	c := v.Client
	out := gen.Client{
		App: c.App, Disabled: c.Disabled, Id: c.ID, Name: c.Name,
		Source: gen.ClientSource(c.Source), Type: gen.ClientType(c.Type),
	}
	if c.Type == domain.ClientTypePublic {
		redirect, post := append([]string{}, c.RedirectURIs...), append([]string{}, c.PostLogoutRedirectURIs...)
		out.RedirectUris, out.PostLogoutRedirectUris = &redirect, &post
	} else {
		keys := make([]gen.ClientKey, 0, len(v.Keys))
		for _, k := range v.Keys {
			keys = append(keys, genClientKey(k))
		}
		out.Keys = &keys
	}
	return out
}

func genAssignments(items []domain.RoleAssignment) []gen.RoleAssignment {
	out := make([]gen.RoleAssignment, 0, len(items))
	for _, a := range items {
		out = append(out, genAssignment(a))
	}
	return out
}

func genAssignment(a domain.RoleAssignment) gen.RoleAssignment {
	return gen.RoleAssignment{Pending: a.Pending, Role: a.Role.String(), Source: gen.AssignmentSource(a.Source)}
}

func jwkInput(j gen.JsonWebKey) commands.JWKInput {
	k := domain.PublicJWK{Kty: string(j.Kty), Crv: string(j.Crv), X: j.X, Y: j.Y, Kid: j.Kid}
	if j.Use != nil {
		k.Use = string(*j.Use)
	}
	if j.Alg != nil {
		k.Alg = string(*j.Alg)
	}
	in := commands.JWKInput{Key: k}
	for name := range j.AdditionalProperties {
		in.Extra = append(in.Extra, name)
	}
	sort.Strings(in.Extra)
	return in
}

// --- users ---

// UsersList lists the users.
func (s *Server) UsersList(ctx context.Context, r gen.UsersListRequestObject) (gen.UsersListResponseObject, error) {
	p, err := s.d.Admin.ListUsers(ctx, listPage(r.Params.PageSize, r.Params.PageToken))
	if err != nil {
		return nil, err
	}
	items := make([]gen.User, 0, len(p.Items))
	for _, u := range p.Items {
		items = append(items, genUser(u))
	}
	return gen.UsersList200JSONResponse{Items: items, NextPageToken: nextToken(p.Next)}, nil
}

// UsersCreate makes a user and an invite.
func (s *Server) UsersCreate(ctx context.Context, r gen.UsersCreateRequestObject) (gen.UsersCreateResponseObject, error) {
	if r.Body == nil {
		return nil, apperrors.NewInvalidInput("the body is required")
	}
	res, err := s.d.CreateUser.Execute(ctx, commands.CreateUser{Email: r.Body.Email, Name: r.Body.Name})
	if err != nil {
		return nil, err
	}
	s.d.Admin.LogChange(ctx, actorID(ctx), "Users_create", res.User.ID)
	return gen.UsersCreate201JSONResponse{
		Body:    gen.UserCreated{User: genUser(res.User), Invite: gen.Invite{ExpiresAt: res.Invite.ExpiresAt, Url: res.Invite.URL}},
		Headers: gen.UsersCreate201ResponseHeaders{CacheControl: "no-store", Pragma: "no-cache"},
	}, nil
}

// UsersGet returns a user.
func (s *Server) UsersGet(ctx context.Context, r gen.UsersGetRequestObject) (gen.UsersGetResponseObject, error) {
	u, err := s.d.Admin.GetUser(ctx, r.UserId)
	if err != nil {
		return nil, err
	}
	return gen.UsersGet200JSONResponse(genUser(u)), nil
}

// UsersUpdate changes the name or the state of a user.
func (s *Server) UsersUpdate(ctx context.Context, r gen.UsersUpdateRequestObject) (gen.UsersUpdateResponseObject, error) {
	if r.Body == nil {
		return nil, apperrors.NewInvalidInput("the body is required")
	}
	u, err := s.d.Admin.UpdateUser(ctx, actorID(ctx), r.UserId, r.Body.Name, r.Body.Disabled)
	if err != nil {
		return nil, err
	}
	return gen.UsersUpdate200JSONResponse(genUser(u)), nil
}

// InvitesCreate makes an invite for a user with the status invited.
func (s *Server) InvitesCreate(ctx context.Context, r gen.InvitesCreateRequestObject) (gen.InvitesCreateResponseObject, error) {
	link, err := s.d.CreateInvite.Execute(ctx, commands.CreateInvite{UserID: r.UserId})
	if err != nil {
		return nil, err
	}
	s.d.Admin.LogChange(ctx, actorID(ctx), "Invites_create", r.UserId)
	return gen.InvitesCreate201JSONResponse{
		Body:    gen.Invite{ExpiresAt: link.ExpiresAt, Url: link.URL},
		Headers: gen.InvitesCreate201ResponseHeaders{CacheControl: "no-store", Pragma: "no-cache"},
	}, nil
}

// MeGet returns the user of the token. A service token gets 403.
func (s *Server) MeGet(ctx context.Context, _ gen.MeGetRequestObject) (gen.MeGetResponseObject, error) {
	p, _ := auth.PrincipalFromContext(ctx)
	if p.Type != auth.PrincipalUser {
		return nil, apperrors.NewProblem(http.StatusForbidden, "forbidden", "The token is not the token of a user.")
	}
	u, err := s.d.Admin.GetUser(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	return gen.MeGet200JSONResponse(genUser(u)), nil
}

// --- user roles ---

// UserRolesList lists the role assignments of a user.
func (s *Server) UserRolesList(ctx context.Context, r gen.UserRolesListRequestObject) (gen.UserRolesListResponseObject, error) {
	p, err := s.d.Admin.ListUserRoles(ctx, r.UserId, listPage(r.Params.PageSize, r.Params.PageToken))
	if err != nil {
		return nil, err
	}
	return gen.UserRolesList200JSONResponse{Items: genAssignments(p.Items), NextPageToken: nextToken(p.Next)}, nil
}

// UserRolesAssign gives a role to a user.
func (s *Server) UserRolesAssign(ctx context.Context, r gen.UserRolesAssignRequestObject) (gen.UserRolesAssignResponseObject, error) {
	ref, err := parseRole(r.Role)
	if err != nil {
		return nil, err
	}
	a, err := s.d.Admin.AssignUserRole(ctx, actorID(ctx), r.UserId, ref)
	if err != nil {
		return nil, err
	}
	return gen.UserRolesAssign200JSONResponse(genAssignment(a)), nil
}

// UserRolesRemove removes a role from a user.
func (s *Server) UserRolesRemove(ctx context.Context, r gen.UserRolesRemoveRequestObject) (gen.UserRolesRemoveResponseObject, error) {
	ref, err := parseRole(r.Role)
	if err != nil {
		return nil, err
	}
	if err := s.d.Admin.RemoveUserRole(ctx, actorID(ctx), r.UserId, ref); err != nil {
		return nil, err
	}
	return gen.UserRolesRemove204Response{}, nil
}

// --- sessions ---

// SessionsList lists the sessions of a user.
func (s *Server) SessionsList(ctx context.Context, r gen.SessionsListRequestObject) (gen.SessionsListResponseObject, error) {
	p, err := s.d.Admin.ListSessions(ctx, r.UserId, listPage(r.Params.PageSize, r.Params.PageToken))
	if err != nil {
		return nil, err
	}
	items := make([]gen.Session, 0, len(p.Items))
	for _, x := range p.Items {
		g := gen.Session{CreatedAt: x.CreatedAt, ExpiresAt: x.ExpiresAt, Id: x.ID, LastSeenAt: x.LastSeenAt, UserId: x.UserID}
		if x.UserAgent != "" {
			ua := x.UserAgent
			g.UserAgent = &ua
		}
		if x.IPAddress != "" {
			ip := x.IPAddress
			g.IpAddress = &ip
		}
		items = append(items, g)
	}
	return gen.SessionsList200JSONResponse{Items: items, NextPageToken: nextToken(p.Next)}, nil
}

// SessionsRevoke revokes one session.
func (s *Server) SessionsRevoke(ctx context.Context, r gen.SessionsRevokeRequestObject) (gen.SessionsRevokeResponseObject, error) {
	if err := s.d.Admin.RevokeSession(ctx, actorID(ctx), r.SessionId); err != nil {
		return nil, err
	}
	return gen.SessionsRevoke204Response{}, nil
}

// SessionsRevokeAll revokes all sessions of a user.
func (s *Server) SessionsRevokeAll(ctx context.Context, r gen.SessionsRevokeAllRequestObject) (gen.SessionsRevokeAllResponseObject, error) {
	if err := s.d.Admin.RevokeUserSessions(ctx, actorID(ctx), r.UserId); err != nil {
		return nil, err
	}
	return gen.SessionsRevokeAll204Response{}, nil
}

// --- clients ---

// ClientsList lists the clients.
func (s *Server) ClientsList(ctx context.Context, r gen.ClientsListRequestObject) (gen.ClientsListResponseObject, error) {
	p, err := s.d.Admin.ListClients(ctx, listPage(r.Params.PageSize, r.Params.PageToken))
	if err != nil {
		return nil, err
	}
	items := make([]gen.Client, 0, len(p.Items))
	for _, v := range p.Items {
		items = append(items, genClient(v))
	}
	return gen.ClientsList200JSONResponse{Items: items, NextPageToken: nextToken(p.Next)}, nil
}

// ClientsCreate makes a client.
func (s *Server) ClientsCreate(ctx context.Context, r gen.ClientsCreateRequestObject) (gen.ClientsCreateResponseObject, error) {
	if r.Body == nil {
		return nil, apperrors.NewInvalidInput("the body is required")
	}
	b := r.Body
	in := commands.CreateClientInput{Type: domain.ClientType(b.Type), App: b.App, Name: b.Name}
	if b.RedirectUris != nil {
		in.RedirectURIs = *b.RedirectUris
	}
	if b.PostLogoutRedirectUris != nil {
		in.PostLogoutRedirectURIs = *b.PostLogoutRedirectUris
	}
	if b.Jwk != nil {
		j := jwkInput(*b.Jwk)
		in.JWK = &j
	}
	v, err := s.d.Admin.CreateClient(ctx, actorID(ctx), in)
	if err != nil {
		return nil, err
	}
	return gen.ClientsCreate201JSONResponse(genClient(v)), nil
}

// ClientsGet returns a client.
func (s *Server) ClientsGet(ctx context.Context, r gen.ClientsGetRequestObject) (gen.ClientsGetResponseObject, error) {
	v, err := s.d.Admin.GetClient(ctx, r.ClientId)
	if err != nil {
		return nil, err
	}
	return gen.ClientsGet200JSONResponse(genClient(v)), nil
}

// ClientsUpdate changes a client.
func (s *Server) ClientsUpdate(ctx context.Context, r gen.ClientsUpdateRequestObject) (gen.ClientsUpdateResponseObject, error) {
	if r.Body == nil {
		return nil, apperrors.NewInvalidInput("the body is required")
	}
	b := r.Body
	in := commands.UpdateClientInput{
		Name: b.Name, RedirectURIs: b.RedirectUris, PostLogoutRedirectURIs: b.PostLogoutRedirectUris, Disabled: b.Disabled,
	}
	if b.Type != nil {
		t := domain.ClientType(*b.Type)
		in.Type = &t
	}
	v, err := s.d.Admin.UpdateClient(ctx, actorID(ctx), r.ClientId, in)
	if err != nil {
		return nil, err
	}
	return gen.ClientsUpdate200JSONResponse(genClient(v)), nil
}

// ClientKeysAdd adds a key to a service client.
func (s *Server) ClientKeysAdd(ctx context.Context, r gen.ClientKeysAddRequestObject) (gen.ClientKeysAddResponseObject, error) {
	if r.Body == nil {
		return nil, apperrors.NewInvalidInput("the body is required")
	}
	k, err := s.d.Admin.AddClientKey(ctx, actorID(ctx), r.ClientId, jwkInput(*r.Body))
	if err != nil {
		return nil, err
	}
	return gen.ClientKeysAdd201JSONResponse(genClientKey(k)), nil
}

// ClientKeysRemove removes a key of a service client.
func (s *Server) ClientKeysRemove(ctx context.Context, r gen.ClientKeysRemoveRequestObject) (gen.ClientKeysRemoveResponseObject, error) {
	if err := s.d.Admin.RemoveClientKey(ctx, actorID(ctx), r.ClientId, r.Kid); err != nil {
		return nil, err
	}
	return gen.ClientKeysRemove204Response{}, nil
}

// ClientRolesList lists the role assignments of a service client.
func (s *Server) ClientRolesList(ctx context.Context, r gen.ClientRolesListRequestObject) (gen.ClientRolesListResponseObject, error) {
	p, err := s.d.Admin.ListClientRoles(ctx, r.ClientId, listPage(r.Params.PageSize, r.Params.PageToken))
	if err != nil {
		return nil, err
	}
	return gen.ClientRolesList200JSONResponse{Items: genAssignments(p.Items), NextPageToken: nextToken(p.Next)}, nil
}

// ClientRolesAssign gives a role to a service client.
func (s *Server) ClientRolesAssign(ctx context.Context, r gen.ClientRolesAssignRequestObject) (gen.ClientRolesAssignResponseObject, error) {
	ref, err := parseRole(r.Role)
	if err != nil {
		return nil, err
	}
	a, err := s.d.Admin.AssignClientRole(ctx, actorID(ctx), r.ClientId, ref)
	if err != nil {
		return nil, err
	}
	return gen.ClientRolesAssign200JSONResponse(genAssignment(a)), nil
}

// ClientRolesRemove removes a role from a service client.
func (s *Server) ClientRolesRemove(ctx context.Context, r gen.ClientRolesRemoveRequestObject) (gen.ClientRolesRemoveResponseObject, error) {
	ref, err := parseRole(r.Role)
	if err != nil {
		return nil, err
	}
	if err := s.d.Admin.RemoveClientRole(ctx, actorID(ctx), r.ClientId, ref); err != nil {
		return nil, err
	}
	return gen.ClientRolesRemove204Response{}, nil
}

// rejectUnknownClientFields makes PATCH /v1/clients/{id} strict. The body has
// the members of ClientUpdate only. A body with app, or with another unknown
// member, gives 400. The generated decoder does not reject unknown members.
func (s *Server) rejectUnknownClientFields(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || !strings.HasPrefix(r.URL.Path, "/v1/clients/") || strings.Count(r.URL.Path, "/") != 3 {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The request is not valid.")
			return
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		var probe gen.ClientUpdate
		if err := dec.Decode(&probe); err != nil {
			s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The request is not valid.")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}
