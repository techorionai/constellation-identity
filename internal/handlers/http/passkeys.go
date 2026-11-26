package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

func passkeyNotFound() error {
	return apperrors.NewProblem(http.StatusNotFound, "passkey_not_found", "The passkey does not exist.")
}

// genPasskey maps a passkey to the contract type. It has no key material. The
// field lastUsedAt is absent when the passkey was not used.
func genPasskey(p domain.Passkey) gen.Passkey {
	out := gen.Passkey{Id: uuid.MustParse(p.ID), Name: p.Name, CreatedAt: p.CreatedAt.UTC(), Synced: p.BackupState}
	if p.LastUsedAt != nil {
		t := p.LastUsedAt.UTC()
		out.LastUsedAt = &t
	}
	return out
}

func genPasskeyPage(p commands.Page[domain.Passkey]) gen.PasskeyPage {
	items := make([]gen.Passkey, 0, len(p.Items))
	for _, x := range p.Items {
		items = append(items, genPasskey(x))
	}
	return gen.PasskeyPage{Items: items, NextPageToken: nextToken(p.Next)}
}

// MePasskeysList lists the passkeys of the user of the token.
func (s *Server) MePasskeysList(ctx context.Context, r gen.MePasskeysListRequestObject) (gen.MePasskeysListResponseObject, error) {
	p, err := userPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	page, err := s.d.MFA.ListPasskeys(ctx, p.ID, listPage(r.Params.PageSize, r.Params.PageToken), false)
	if err != nil {
		return nil, err
	}
	return gen.MePasskeysList200JSONResponse(genPasskeyPage(page)), nil
}

// MePasskeysUpdate renames a passkey of the user of the token. The order of the
// checks is the order of the contract: the token, the scopes,
// user_token_required, reauthentication_required, passkey_not_found, and the
// name (422).
func (s *Server) MePasskeysUpdate(ctx context.Context, r gen.MePasskeysUpdateRequestObject) (gen.MePasskeysUpdateResponseObject, error) {
	p, err := userPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.checkMFA(ctx); err != nil {
		return nil, err
	}
	name := ""
	if r.Body != nil {
		name = r.Body.Name
	}
	pk, err := s.d.MFA.RenamePasskey(ctx, commands.RenamePasskey{
		UserID: p.ID, PasskeyID: r.PasskeyId, Name: name, Actor: p.ID,
	})
	switch {
	case errors.Is(err, commands.ErrPasskeyNotFound):
		return nil, passkeyNotFound()
	case errors.Is(err, domain.ErrInvalidPasskeyName):
		return nil, apperrors.NewValidationError([]domain.FieldError{{
			Code: "invalid_name", Field: "name",
			Message: "The name must have 1 to 64 characters, with no space at the start or the end, and no control character.",
		}})
	case err != nil:
		return nil, err
	}
	return gen.MePasskeysUpdate200JSONResponse(genPasskey(pk)), nil
}

// MePasskeysRemove removes a passkey of the user of the token. The order of the
// checks is the order of the contract.
func (s *Server) MePasskeysRemove(ctx context.Context, r gen.MePasskeysRemoveRequestObject) (gen.MePasskeysRemoveResponseObject, error) {
	p, err := userPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.checkMFA(ctx); err != nil {
		return nil, err
	}
	err = s.d.MFA.RemovePasskey(ctx, commands.RemovePasskey{UserID: p.ID, PasskeyID: r.PasskeyId, Actor: p.ID})
	switch {
	case errors.Is(err, commands.ErrPasskeyNotFound):
		return nil, passkeyNotFound()
	case errors.Is(err, commands.ErrMFARequired):
		return nil, apperrors.NewConflictCode("mfa_required", "The policy requires MFA for the user. The passkey is the last second factor.")
	case err != nil:
		return nil, err
	}
	return gen.MePasskeysRemove204Response{}, nil
}

// UserPasskeysList lists the passkeys of any user.
func (s *Server) UserPasskeysList(ctx context.Context, r gen.UserPasskeysListRequestObject) (gen.UserPasskeysListResponseObject, error) {
	page, err := s.d.MFA.ListPasskeys(ctx, r.UserId, listPage(r.Params.PageSize, r.Params.PageToken), true)
	if errors.Is(err, commands.ErrUserNotFound) {
		return nil, userNotFound()
	}
	if err != nil {
		return nil, err
	}
	return gen.UserPasskeysList200JSONResponse(genPasskeyPage(page)), nil
}
