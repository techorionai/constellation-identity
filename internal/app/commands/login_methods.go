package commands

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/identitylinks"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// maxLinksRead is the number of links that the rule "last login method" reads.
// A user has one link for each provider, so this is more than enough.
const maxLinksRead = 20

// readMethodsState builds the data of the rule "last login method" for a user.
// passkeys is the number of stored passkeys that the rule counts. A nil links
// repository means that no user has a link.
func readMethodsState(ctx context.Context, links identitylinks.Repository, on domain.ProviderOn,
	passkeysOn bool, u domain.User, passkeys int) (domain.MethodsState, error) {
	st := domain.MethodsState{
		HasPassword: u.PasswordHash != "", Passkeys: passkeys, PasskeysOn: passkeysOn, On: on,
	}
	if links == nil {
		return st, nil
	}
	list, err := links.ListByUser(ctx, u.ID, nil, maxLinksRead)
	if err != nil {
		return domain.MethodsState{}, fmt.Errorf("list the links: %w", err)
	}
	for _, l := range list {
		st.Links = append(st.Links, l.Provider)
	}
	return st, nil
}

// hasLoginMethodWith reports whether the user keeps a login method if the user
// has the given number of passkeys.
func (m *MFA) hasLoginMethodWith(ctx context.Context, u domain.User, passkeys int) (bool, error) {
	st, err := readMethodsState(ctx, m.d.Links, m.d.ProviderOn, m.d.PasskeysOn, u, passkeys)
	if err != nil {
		return false, err
	}
	return domain.HasLoginMethod(st), nil
}

// revokeAPITokens revokes the personal API tokens of a user that a session with
// the method made. It runs in the transaction of the caller.
func (m *MFA) revokeAPITokens(ctx context.Context, userID, method string) error {
	if m.d.APITokens == nil {
		return nil
	}
	if _, err := m.d.APITokens.RevokeWithMethod(ctx, userID, method, m.now()); err != nil {
		return fmt.Errorf("revoke the API tokens: %w", err)
	}
	return nil
}

// checkFedLink checks, in the transaction that starts the session, that the user
// still has the link of a login with the method fed (R2). It locks the user
// row, as the removal of a link does. Thus a removal that ran before the check
// stops the login, and a removal that runs after it revokes the new session. A
// pending login that has no link any more gives ErrMFAPendingGone.
func (m *MFA) checkFedLink(ctx context.Context, p domain.PendingLogin) error {
	if !slices.Contains(p.Methods, domain.AMRFederated) {
		return nil
	}
	if _, err := m.d.Users.LockByID(ctx, p.UserID); errors.Is(err, users.ErrNotFound) {
		return ErrMFAPendingGone
	} else if err != nil {
		return err
	}
	if m.d.Links == nil || m.d.ProviderOn == nil {
		return ErrMFAPendingGone
	}
	if p.Provider != "" {
		if !m.d.ProviderOn(p.Provider) {
			return ErrMFAPendingGone
		}
		if _, err := m.d.Links.GetByUserProvider(ctx, p.UserID, p.Provider); errors.Is(err, identitylinks.ErrNotFound) {
			return ErrMFAPendingGone
		} else if err != nil {
			return err
		}
		return nil
	}
	list, err := m.d.Links.ListByUser(ctx, p.UserID, nil, maxLinksRead)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(list, func(l domain.IdentityLink) bool { return m.d.ProviderOn(l.Provider) }) {
		return ErrMFAPendingGone
	}
	return nil
}
