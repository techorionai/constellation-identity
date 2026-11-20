package httpapi

import (
	"context"

	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

// unimplemented gives the operations that later issues implement. Each one
// returns errNotImplemented. The response error handler maps that error to a
// 501 Problem with the code not_implemented.
type unimplemented struct{}

func (unimplemented) OAuthAuthorize(context.Context, gen.OAuthAuthorizeRequestObject) (gen.OAuthAuthorizeResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) OAuthEndSession(context.Context, gen.OAuthEndSessionRequestObject) (gen.OAuthEndSessionResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) OAuthRevoke(context.Context, gen.OAuthRevokeRequestObject) (gen.OAuthRevokeResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) OAuthUserinfo(context.Context, gen.OAuthUserinfoRequestObject) (gen.OAuthUserinfoResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) ClientsList(context.Context, gen.ClientsListRequestObject) (gen.ClientsListResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) ClientsCreate(context.Context, gen.ClientsCreateRequestObject) (gen.ClientsCreateResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) ClientsGet(context.Context, gen.ClientsGetRequestObject) (gen.ClientsGetResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) ClientsUpdate(context.Context, gen.ClientsUpdateRequestObject) (gen.ClientsUpdateResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) ClientKeysAdd(context.Context, gen.ClientKeysAddRequestObject) (gen.ClientKeysAddResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) ClientKeysRemove(context.Context, gen.ClientKeysRemoveRequestObject) (gen.ClientKeysRemoveResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) ClientRolesList(context.Context, gen.ClientRolesListRequestObject) (gen.ClientRolesListResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) ClientRolesRemove(context.Context, gen.ClientRolesRemoveRequestObject) (gen.ClientRolesRemoveResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) ClientRolesAssign(context.Context, gen.ClientRolesAssignRequestObject) (gen.ClientRolesAssignResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) MeGet(context.Context, gen.MeGetRequestObject) (gen.MeGetResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) PermissionManifestsList(context.Context, gen.PermissionManifestsListRequestObject) (gen.PermissionManifestsListResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) PermissionManifestsGet(context.Context, gen.PermissionManifestsGetRequestObject) (gen.PermissionManifestsGetResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) PermissionManifestsPublish(context.Context, gen.PermissionManifestsPublishRequestObject) (gen.PermissionManifestsPublishResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) RolesList(context.Context, gen.RolesListRequestObject) (gen.RolesListResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) RolesGet(context.Context, gen.RolesGetRequestObject) (gen.RolesGetResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) SessionsRevoke(context.Context, gen.SessionsRevokeRequestObject) (gen.SessionsRevokeResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) UsersList(context.Context, gen.UsersListRequestObject) (gen.UsersListResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) UsersCreate(context.Context, gen.UsersCreateRequestObject) (gen.UsersCreateResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) UsersGet(context.Context, gen.UsersGetRequestObject) (gen.UsersGetResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) UsersUpdate(context.Context, gen.UsersUpdateRequestObject) (gen.UsersUpdateResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) InvitesCreate(context.Context, gen.InvitesCreateRequestObject) (gen.InvitesCreateResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) UserRolesList(context.Context, gen.UserRolesListRequestObject) (gen.UserRolesListResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) UserRolesRemove(context.Context, gen.UserRolesRemoveRequestObject) (gen.UserRolesRemoveResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) UserRolesAssign(context.Context, gen.UserRolesAssignRequestObject) (gen.UserRolesAssignResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) SessionsRevokeAll(context.Context, gen.SessionsRevokeAllRequestObject) (gen.SessionsRevokeAllResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) SessionsList(context.Context, gen.SessionsListRequestObject) (gen.SessionsListResponseObject, error) {
	return nil, errNotImplemented
}
