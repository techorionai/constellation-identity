package commands

import (
	"context"
	"fmt"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/identitylinks"
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
