package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/techorionai/constellation-platform-go/transaction"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/apitokens"
	"github.com/techorionai/constellation-identity/internal/ports/identitylinks"
	"github.com/techorionai/constellation-identity/internal/ports/mfa"
	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// Errors of the identity links. A handler maps them to a page or a status.
var (
	// ErrIdentityLinkNotFound means the user has no link for the provider, or the
	// provider name is not valid.
	ErrIdentityLinkNotFound = errors.New("identity_link_not_found")
)

// IdentityLinksDeps are the ports of the use cases of the identity links.
type IdentityLinksDeps struct {
	Users     users.Repository
	Links     identitylinks.Repository
	Sessions  sessions.Repository
	APITokens apitokens.Repository
	MFA       mfa.Repository
	Events    securityevents.Events
	Tx        transaction.Transactor
	// PasskeysOn is true when the service accepts passkeys. ProviderOn tells if a
	// provider is on.
	PasskeysOn bool
	ProviderOn domain.ProviderOn
	Log        *slog.Logger
	// Now is the clock. The default is time.Now.
	Now Clock
}

// IdentityLinks has the use cases that list and remove the upstream links.
type IdentityLinks struct{ d IdentityLinksDeps }

// NewIdentityLinks makes the use cases.
func NewIdentityLinks(d IdentityLinksDeps) *IdentityLinks {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &IdentityLinks{d: d}
}

func (l *IdentityLinks) now() time.Time { return l.d.Now().UTC().Truncate(time.Microsecond) }

// List returns a page of the links of a user, in order of the creation time and
// the provider. If checkUser is true, it returns ErrUserNotFound for a user that
// does not exist.
func (l *IdentityLinks) List(ctx context.Context, userID string, p ListPage, checkUser bool) (Page[domain.IdentityLink], error) {
	n, err := p.size()
	if err != nil {
		return Page[domain.IdentityLink]{}, err
	}
	cur, err := DecodeTimeCursor(p.Token)
	if err != nil {
		return Page[domain.IdentityLink]{}, err
	}
	if checkUser {
		if !uuidPattern.MatchString(userID) {
			return Page[domain.IdentityLink]{}, ErrUserNotFound
		}
		if _, err := l.d.Users.GetByID(ctx, userID); errors.Is(err, users.ErrNotFound) {
			return Page[domain.IdentityLink]{}, ErrUserNotFound
		} else if err != nil {
			return Page[domain.IdentityLink]{}, fmt.Errorf("get the user: %w", err)
		}
	}
	items, err := l.d.Links.ListByUser(ctx, userID, cur, n+1)
	if err != nil {
		return Page[domain.IdentityLink]{}, fmt.Errorf("list the links: %w", err)
	}
	out := Page[domain.IdentityLink]{Items: items}
	if len(items) > n {
		out.Items = items[:n]
		last := out.Items[n-1]
		out.Next = EncodeTimeCursor(last.CreatedAt, last.Provider)
	}
	return out, nil
}

// RemoveIdentityLink is the input of the removal of a link.
type RemoveIdentityLink struct {
	UserID   string
	Provider string
	// Actor is the ID of the principal that does the removal.
	Actor string
	// CheckUser is true for the admin operation: a user that does not exist gives
	// ErrUserNotFound before any other check.
	CheckUser bool
	// Self is true when the user removes an own link. The removal then needs the
	// proof of a local factor (P23). The admin operation is not a self removal.
	Self bool
	// FactorVerified is true when the caller proved a local factor of the user:
	// the page checked a password or a code, or the token of the API call has a
	// local factor in amr. It matters only with Self.
	FactorVerified bool
}

// Remove removes the link of a user for a provider. The order of the checks:
// ErrUserNotFound (only with CheckUser), ErrIdentityLinkNotFound,
// ErrLastLoginMethod, then ErrLocalFactorMissing and ErrLocalFactorRequired
// (only with Self, P23). The proof of the factor comes before any change. In one transaction after the lock of the user row, it
// removes the link, revokes the sessions and the refresh token families of the
// user with fed in amr (also the current session), and revokes the personal API
// tokens that a session with fed in amr made. Then it writes the audit entry
// and sends the notice.
func (l *IdentityLinks) Remove(ctx context.Context, in RemoveIdentityLink) error {
	if in.CheckUser && !uuidPattern.MatchString(in.UserID) {
		return ErrUserNotFound
	}
	// A name that is not a provider takes no row lock (R18). The admin operation
	// still gives ErrUserNotFound first, with a read that takes no lock.
	if !domain.ValidProvider(in.Provider) {
		if in.CheckUser {
			if _, err := l.d.Users.GetByID(ctx, in.UserID); errors.Is(err, users.ErrNotFound) {
				return ErrUserNotFound
			} else if err != nil {
				return fmt.Errorf("get the user: %w", err)
			}
		}
		return ErrIdentityLinkNotFound
	}
	err := l.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		u, err := l.d.Users.LockByID(ctx, in.UserID)
		if errors.Is(err, users.ErrNotFound) {
			return ErrUserNotFound
		}
		if err != nil {
			return err
		}
		var st domain.MFAState
		if l.d.MFA != nil {
			if st, err = l.d.MFA.State(ctx, u.ID); err != nil {
				return err
			}
		}
		st.PasskeysOn = l.d.PasskeysOn
		if _, err := l.d.Links.GetByUserProvider(ctx, u.ID, in.Provider); errors.Is(err, identitylinks.ErrNotFound) {
			return ErrIdentityLinkNotFound
		} else if err != nil {
			return err
		}
		passkeys := st.Passkeys
		ms, err := readMethodsState(ctx, l.d.Links, l.d.ProviderOn, l.d.PasskeysOn, u, passkeys)
		if err != nil {
			return err
		}
		// The state after the removal: no link of this provider.
		after := ms
		after.Links = nil
		for _, p := range ms.Links {
			if p != in.Provider {
				after.Links = append(after.Links, p)
			}
		}
		if !domain.HasLoginMethod(after) {
			return ErrLastLoginMethod
		}
		// The check comes after the checks of the data and before the first change.
		if in.Self {
			// A user that has a local factor must prove it. A user with no local
			// factor cannot prove anything, and the removal is refused (P23).
			if !domain.HasLocalFactor(u.PasswordHash != "", st) {
				return ErrLocalFactorMissing
			}
			if !in.FactorVerified {
				return ErrLocalFactorRequired
			}
		}
		if err := l.d.Links.Remove(ctx, u.ID, in.Provider); err != nil {
			return err
		}
		now := l.now()
		if _, err := l.d.Sessions.RevokeWithMethod(ctx, u.ID, domain.AMRFederated, now); err != nil {
			return err
		}
		if l.d.APITokens != nil {
			if _, err := l.d.APITokens.RevokeWithMethod(ctx, u.ID, domain.AMRFederated, now); err != nil {
				return err
			}
		}
		return nil
	}, txName("remove_identity_link"))
	if errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrIdentityLinkNotFound) || errors.Is(err, ErrLastLoginMethod) ||
		errors.Is(err, ErrLocalFactorMissing) || errors.Is(err, ErrLocalFactorRequired) {
		return err
	}
	if err != nil {
		return fmt.Errorf("remove the link: %w", err)
	}
	l.d.Log.InfoContext(ctx, "identity.idp.unlinked", "event", "identity.idp.unlinked", "user_id", in.UserID, "provider", in.Provider)
	recordLinkEvent(ctx, l.d.Events, l.d.Log, securityevents.ActionIdentityLinkRemove,
		securityevents.NoticeIdentityLinkRemoved, in.Actor, in.UserID, in.Provider, l.now())
	return nil
}

// recordLinkEvent writes the audit entry and sends the notice of a change of a
// link. A failure is logged and does not undo the change. The entry has the
// provider and no subject and no email.
func recordLinkEvent(ctx context.Context, ev securityevents.Events, log *slog.Logger, action, notice, actor, target, provider string, at time.Time) {
	if ev == nil {
		return
	}
	if err := ev.RecordAudit(ctx, securityevents.AuditEntry{
		Action: action, Actor: actor, TargetUserID: target, Result: securityevents.ResultSuccess, At: at,
		Changes: map[string]string{"provider": provider},
	}); err != nil {
		log.ErrorContext(ctx, "identity.audit.failed", "event", "identity.audit.failed", "action", action, "error", err)
	}
	if err := ev.NotifyUser(ctx, securityevents.Notice{Kind: notice, TargetUserID: target, At: at}); err != nil {
		log.ErrorContext(ctx, "identity.security_notice.failed", "event", "identity.security_notice.failed", "kind", notice, "error", err)
	}
}
