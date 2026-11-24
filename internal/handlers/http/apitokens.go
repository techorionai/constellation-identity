package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/techorionai/constellation-platform-go/auth"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

func genAPIToken(t domain.APIToken) gen.ApiToken {
	return gen.ApiToken{
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, Id: uuid.MustParse(t.ID), LastUsedAt: t.LastUsedAt,
		Name: t.Name, RevokedAt: t.RevokedAt, Scope: strings.Join(t.Scope, " "), UserId: t.UserID,
	}
}

func genAPITokenPage(p commands.Page[domain.APIToken]) gen.ApiTokenPage {
	items := make([]gen.ApiToken, 0, len(p.Items))
	for _, t := range p.Items {
		items = append(items, genAPIToken(t))
	}
	return gen.ApiTokenPage{Items: items, NextPageToken: nextToken(p.Next)}
}

// userPrincipal returns the principal of a self-service call. It must be a user
// with an access token, and not an acting principal (RFC 8693). Else the call
// gets 403 user_token_required.
func userPrincipal(ctx context.Context) (auth.Principal, error) {
	p, ok := auth.PrincipalFromContext(ctx)
	if !ok || p.Type != auth.PrincipalUser || p.Act != nil || p.TokenType.OrAccess() != auth.TokenTypeAccess {
		return auth.Principal{}, apperrors.NewProblem(http.StatusForbidden, "user_token_required", "The call needs the access token of a user.")
	}
	return p, nil
}

// MeApiTokensList lists the API tokens of the user of the token.
func (s *Server) MeApiTokensList(ctx context.Context, r gen.MeApiTokensListRequestObject) (gen.MeApiTokensListResponseObject, error) {
	p, err := userPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	page, err := s.d.APITokens.List(ctx, p.ID, listPage(r.Params.PageSize, r.Params.PageToken))
	if err != nil {
		return nil, err
	}
	return gen.MeApiTokensList200JSONResponse(genAPITokenPage(page)), nil
}

// MeApiTokensCreate makes an API token for the user of the token.
func (s *Server) MeApiTokensCreate(ctx context.Context, r gen.MeApiTokensCreateRequestObject) (gen.MeApiTokensCreateResponseObject, error) {
	p, err := userPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apperrors.NewInvalidInput("the body is required")
	}
	created, err := s.d.APITokens.Create(ctx, commands.CreateAPIToken{
		UserID: p.ID, Name: r.Body.Name, Scope: r.Body.Scope, ExpiresInDays: r.Body.ExpiresInDays,
	})
	if err != nil {
		return nil, err
	}
	t := genAPIToken(created.Token)
	return gen.MeApiTokensCreate201JSONResponse{
		Body: gen.ApiTokenCreated{
			CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, Id: t.Id, LastUsedAt: t.LastUsedAt, Name: t.Name,
			RevokedAt: t.RevokedAt, Scope: t.Scope, Token: created.Value, UserId: t.UserId,
		},
		Headers: gen.MeApiTokensCreate201ResponseHeaders{CacheControl: "no-store", Pragma: "no-cache"},
	}, nil
}

// MeApiTokensRevoke revokes an API token of the user of the token.
func (s *Server) MeApiTokensRevoke(ctx context.Context, r gen.MeApiTokensRevokeRequestObject) (gen.MeApiTokensRevokeResponseObject, error) {
	p, err := userPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.d.APITokens.Revoke(ctx, p.ID, r.TokenId); err != nil {
		return nil, err
	}
	return gen.MeApiTokensRevoke204Response{}, nil
}

// UserApiTokensList lists the API tokens of any user.
func (s *Server) UserApiTokensList(ctx context.Context, r gen.UserApiTokensListRequestObject) (gen.UserApiTokensListResponseObject, error) {
	page, err := s.d.APITokens.ListForUser(ctx, r.UserId, listPage(r.Params.PageSize, r.Params.PageToken))
	if err != nil {
		return nil, err
	}
	return gen.UserApiTokensList200JSONResponse(genAPITokenPage(page)), nil
}

// ApiTokensRevoke revokes any API token.
func (s *Server) ApiTokensRevoke(ctx context.Context, r gen.ApiTokensRevokeRequestObject) (gen.ApiTokensRevokeResponseObject, error) {
	if err := s.d.APITokens.AdminRevoke(ctx, actorID(ctx), r.TokenId); err != nil {
		return nil, err
	}
	return gen.ApiTokensRevoke204Response{}, nil
}

// OAuthIntrospect answers an introspection request (RFC 7662). Only a service
// client can call it. The response never says why a token is not active.
func (s *Server) OAuthIntrospect(ctx context.Context, _ gen.OAuthIntrospectRequestObject) (gen.OAuthIntrospectResponseObject, error) {
	tr, _ := ctx.Value(tokenRequestKey{}).(tokenRequest)
	field := func(name string) string { return tr.post.Get(name) }
	res, err := s.d.Introspect.Execute(ctx, commands.Introspect{
		Token: field("token"), ClientID: field("client_id"),
		AssertionType: field("client_assertion_type"), Assertion: field("client_assertion"),
		SecondAuthentication: tr.secondAuthentication, RepeatedParameter: tr.repeated,
	})
	if err != nil {
		return nil, err
	}
	headers := gen.OAuthIntrospect200ResponseHeaders{CacheControl: "no-store", Pragma: "no-cache"}
	if !res.Active {
		return gen.OAuthIntrospect200JSONResponse{Body: gen.IntrospectResponse{Active: false}, Headers: headers}, nil
	}
	scope := strings.Join(res.Scope, " ")
	principal := gen.PrincipalType(auth.PrincipalUser)
	var tokenType gen.IntrospectedTokenType
	if err := tokenType.FromIntrospectedTokenType0(gen.IntrospectedTokenType0ApiToken); err != nil {
		return nil, err
	}
	return gen.OAuthIntrospect200JSONResponse{
		Body: gen.IntrospectResponse{
			Active: true, Scope: &scope, Sub: &res.Sub, Aud: &res.Aud, Exp: &res.Exp, Iat: &res.Iat, Jti: &res.JTI,
			TokenType: &tokenType, PrincipalType: &principal,
		},
		Headers: headers,
	}, nil
}
