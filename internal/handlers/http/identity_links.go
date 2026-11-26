package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/techorionai/constellation-platform-go/auth"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

// freshLoginChallenge is the value of WWW-Authenticate for a refusal that needs
// a fresh login and no second factor (RFC 9470). platform-go gives the challenge
// of the MFA check only, so the service has this one.
const freshLoginChallenge = `Bearer error="insufficient_user_authentication", error_description="A fresh login is necessary", max_age="300"`

// errFreshLoginRequired makes the 401 refusal of a check that needs a fresh
// login and does not check mfa.
var errFreshLoginRequired = errors.New("fresh login required")

// writeFreshLoginRequired writes the 401 refusal: the header WWW-Authenticate,
// and a problem body with the code reauthentication_required.
func (s *Server) writeFreshLoginRequired(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", freshLoginChallenge)
	s.writeProblem(w, r, http.StatusUnauthorized, "reauthentication_required", "Reauthentication required", "A fresh login is necessary.")
}

// checkFreshLogin runs the check of a fresh login after the scope check and the
// check user_token_required. It needs a user token with no act and with an
// auth_time of at most 5 minutes. It does not check mfa. A token with no
// auth_time and an API token fail. It uses the clock of the service.
func (s *Server) checkFreshLogin(ctx context.Context) error {
	p, ok := auth.PrincipalFromContext(ctx)
	if !ok || p.Act != nil || p.TokenType.OrAccess() == auth.TokenTypeAPI {
		return errFreshLoginRequired
	}
	if p.AuthTime.IsZero() || s.now().Sub(p.AuthTime) > mfaMaxAge {
		return errFreshLoginRequired
	}
	return nil
}

func identityLinkNotFound() error {
	return apperrors.NewProblem(http.StatusNotFound, "identity_link_not_found", "The user has no link for this provider.")
}

func lastLoginMethod() error {
	return apperrors.NewConflictCode("last_login_method", "The change would leave the user with no login method.")
}

// genIdentityLink maps a link to the contract type. It has no subject.
func genIdentityLink(l domain.IdentityLink) gen.IdentityLink {
	out := gen.IdentityLink{CreatedAt: l.CreatedAt.UTC()}
	_ = out.Provider.FromUpstreamProvider1(l.Provider)
	if l.Email != "" {
		e := l.Email
		out.Email = &e
	}
	if l.LastUsedAt != nil {
		t := l.LastUsedAt.UTC()
		out.LastUsedAt = &t
	}
	return out
}

func genIdentityLinkPage(p commands.Page[domain.IdentityLink]) gen.IdentityLinkPage {
	items := make([]gen.IdentityLink, 0, len(p.Items))
	for _, l := range p.Items {
		items = append(items, genIdentityLink(l))
	}
	return gen.IdentityLinkPage{Items: items, NextPageToken: nextToken(p.Next)}
}

// MeIdentityLinksList lists the upstream links of the user of the token.
func (s *Server) MeIdentityLinksList(ctx context.Context, r gen.MeIdentityLinksListRequestObject) (gen.MeIdentityLinksListResponseObject, error) {
	p, err := userPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	page, err := s.d.IdentityLinks.List(ctx, p.ID, listPage(r.Params.PageSize, r.Params.PageToken), false)
	if err != nil {
		return nil, err
	}
	return gen.MeIdentityLinksList200JSONResponse(genIdentityLinkPage(page)), nil
}

// MeIdentityLinksRemove removes a link of the user of the token. The order of
// the checks is the order of the contract: the token, the scopes,
// user_token_required, reauthentication_required, identity_link_not_found, and
// last_login_method.
func (s *Server) MeIdentityLinksRemove(ctx context.Context, r gen.MeIdentityLinksRemoveRequestObject) (gen.MeIdentityLinksRemoveResponseObject, error) {
	p, err := userPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.checkFreshLogin(ctx); err != nil {
		return nil, err
	}
	// The API call cannot carry a password or a code. The token must show that
	// the login used a local factor (pwd, otp, rec, or hwk in amr), and the user
	// must have one (P23). A user with no local factor needs a token of an
	// upstream login whose ID token had a valid auth_time (fed_auth_time in
	// amr). A token of a login with only an upstream account does not pass for a
	// user with a local factor. The user then logs in with the local factor, or
	// uses the page.
	err = s.d.IdentityLinks.Remove(ctx, commands.RemoveIdentityLink{
		UserID: p.ID, Provider: r.Provider, Actor: p.ID, Self: true,
		FactorVerified: slices.ContainsFunc(p.AuthMethods, domain.LocalFactorMethod),
		UpstreamFresh:  slices.Contains(p.AuthMethods, domain.AMRFederated) && slices.Contains(p.AuthMethods, domain.AMRFederatedAuthTime),
	})
	if errors.Is(err, commands.ErrLocalFactorRequired) || errors.Is(err, commands.ErrLocalFactorMissing) {
		return nil, errFreshLoginRequired
	}
	if err := mapLinkRemoveError(err); err != nil {
		return nil, err
	}
	return gen.MeIdentityLinksRemove204Response{}, nil
}

// UserIdentityLinksList lists the upstream links of any user.
func (s *Server) UserIdentityLinksList(ctx context.Context, r gen.UserIdentityLinksListRequestObject) (gen.UserIdentityLinksListResponseObject, error) {
	page, err := s.d.IdentityLinks.List(ctx, r.UserId, listPage(r.Params.PageSize, r.Params.PageToken), true)
	if errors.Is(err, commands.ErrUserNotFound) {
		return nil, userNotFound()
	}
	if err != nil {
		return nil, err
	}
	return gen.UserIdentityLinksList200JSONResponse(genIdentityLinkPage(page)), nil
}

// UserIdentityLinksRemove removes a link of any user. The token needs a fresh
// MFA login. The order of the checks is the order of the contract.
func (s *Server) UserIdentityLinksRemove(ctx context.Context, r gen.UserIdentityLinksRemoveRequestObject) (gen.UserIdentityLinksRemoveResponseObject, error) {
	if err := s.checkMFA(ctx); err != nil {
		return nil, err
	}
	err := s.d.IdentityLinks.Remove(ctx, commands.RemoveIdentityLink{
		UserID: r.UserId, Provider: r.Provider, Actor: actorID(ctx), CheckUser: true,
	})
	if err := mapLinkRemoveError(err); err != nil {
		return nil, err
	}
	return gen.UserIdentityLinksRemove204Response{}, nil
}

// mapLinkRemoveError maps the error of the removal of a link to a problem. It
// returns nil for nil.
func mapLinkRemoveError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, commands.ErrUserNotFound):
		return userNotFound()
	case errors.Is(err, commands.ErrIdentityLinkNotFound):
		return identityLinkNotFound()
	case errors.Is(err, commands.ErrLastLoginMethod):
		return lastLoginMethod()
	}
	return err
}
