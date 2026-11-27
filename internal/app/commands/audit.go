package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/techorionai/constellation-platform-go/audit"
	"github.com/techorionai/constellation-platform-go/auth"
	"github.com/techorionai/constellation-platform-go/transaction"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
)

// The actions of the audit entries of the identity service. The entry has the
// result success, unless the text says other. The audit writer takes the actor
// from the principal of the context.
const (
	ActionTotpRemove       = "identity:mfa:totp_remove"
	ActionMfaReset         = "identity:mfa:reset"
	ActionPasskeyAdd       = "identity:mfa:passkey_add"    //nolint:gosec // G101: This is the name of an action, not a credential.
	ActionPasskeyRename    = "identity:mfa:passkey_rename" //nolint:gosec // G101: This is the name of an action, not a credential.
	ActionPasskeyRemove    = "identity:mfa:passkey_remove" //nolint:gosec // G101: This is the name of an action, not a credential.
	ActionLinkAdd          = "identity:identity_link:add"
	ActionLinkRemove       = "identity:identity_link:remove"
	ActionPasswordSet      = "identity:password:set"
	ActionUserCreate       = "identity:user:create"
	ActionUserUpdate       = "identity:user:update"
	ActionInviteCreate     = "identity:invite:create"
	ActionInviteAccept     = "identity:invite:accept"
	ActionSetupComplete    = "identity:setup:complete"
	ActionUserRoleAssign   = "identity:user_role:assign"
	ActionUserRoleRemove   = "identity:user_role:remove"
	ActionSessionRevoke    = "identity:session:revoke"
	ActionSessionRevokeAll = "identity:session:revoke_all"
	ActionClientCreate     = "identity:client:create"
	ActionClientUpdate     = "identity:client:update"
	ActionClientSync       = "identity:client:sync"
	ActionClientKeyAdd     = "identity:client_key:add"
	ActionClientKeyRemove  = "identity:client_key:remove"
	ActionClientRoleAssign = "identity:client_role:assign"
	ActionClientRoleRemove = "identity:client_role:remove"
	ActionAgentCreate      = "identity:agent:create"
	ActionAgentUpdate      = "identity:agent:update"
	ActionAgentRoleAssign  = "identity:agent_role:assign"
	ActionAgentRoleRemove  = "identity:agent_role:remove"
	ActionAPITokenCreate   = "identity:api_token:create" //nolint:gosec // G101: This is the name of an action, not a credential.
	ActionAPITokenRevoke   = "identity:api_token:revoke" //nolint:gosec // G101: This is the name of an action, not a credential.
	ActionManifestPublish  = "identity:manifest:publish"
)

// The values of details.origin. A flow with no principal in the context has an
// origin. The audit actor is then the service identity.
const (
	OriginCLI          = "cli"
	OriginInvite       = "invite"
	OriginSetup        = "setup"
	OriginPasswordLink = "password_link"
)

// The target types of the audit entries.
const (
	targetUser     = "user"
	targetClient   = "client"
	targetAgent    = "agent"
	targetSession  = "session"
	targetAPIToken = "api_token"
	targetManifest = "manifest"
)

// ErrNoAuditWriter means a use case that must write an audit entry has no
// audit writer. The use case then stops, so that no change has no entry.
var ErrNoAuditWriter = errors.New("the audit writer is not set")

// writeAudit writes one audit entry with the result success. It must run in
// the transaction of the change. An error stops the change.
func writeAudit(ctx context.Context, w audit.Writer, at time.Time, action, targetType, targetID string, details map[string]any) error {
	if w == nil {
		return ErrNoAuditWriter
	}
	e := audit.Entry{Action: action, Result: audit.Success, Time: at, Details: details}
	if targetID != "" {
		e.Target = &audit.Target{Type: targetType, ID: targetID}
	}
	if err := w.Write(ctx, e); err != nil {
		// The change rolls back. The client gets 503, because the audit store is a
		// dependency that the request needs.
		return apperrors.NewUnavailable(fmt.Errorf("write the audit entry %s: %w", action, err), "The audit entry cannot be written.")
	}
	return nil
}

// originDetails returns the details of an entry with details.origin. An empty
// origin gives the details without it.
func originDetails(origin string, details map[string]any) map[string]any {
	if origin == "" {
		return details
	}
	out := make(map[string]any, len(details)+1)
	for k, v := range details {
		out[k] = v
	}
	out["origin"] = origin
	return out
}

// asUser returns a context with the user as the authenticated principal. A use
// case calls it only after it checked the session of the user. The audit writer
// then takes the user as the actor of the entry.
func asUser(ctx context.Context, userID string) context.Context {
	return auth.ContextWithPrincipal(ctx, auth.Principal{ID: userID, Type: auth.PrincipalUser})
}

// DeniedAudit writes the audit entry of an admin request that the scope check
// denied. The request has no change. The entry has its own short transaction.
type DeniedAudit struct {
	tx    transaction.Transactor
	audit audit.Writer
}

// NewDeniedAudit makes the use case.
func NewDeniedAudit(tx transaction.Transactor, w audit.Writer) *DeniedAudit {
	return &DeniedAudit{tx: tx, audit: w}
}

// Record writes one entry with the result denied and no target. The audit
// writer takes the actor from the principal of the context. missingScopes are
// the scopes that the principal does not have. They are permission keys, not
// secrets.
func (d *DeniedAudit) Record(ctx context.Context, action string, missingScopes []string) error {
	if d == nil || d.tx == nil || d.audit == nil {
		return ErrNoAuditWriter
	}
	e := audit.Entry{Action: action, Result: audit.Denied, Details: map[string]any{"missingScopes": missingScopes}}
	return d.tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := d.audit.Write(ctx, e); err != nil {
			return fmt.Errorf("write the audit entry %s: %w", action, err)
		}
		return nil
	}, txName("audit_denied"))
}

// The actions of the audit entries of the tokens, the logins, and the operator
// commands.
const (
	ActionTokenIssue   = "identity:token:issue"
	ActionSessionLogin = "identity:session:login"
	ActionLoginUnlock  = "identity:login:unlock"
	ActionSetupLinkNew = "identity:setup:link_create"
	ActionIdpSecretSet = "identity:idp:secret_set" //nolint:gosec // G101: This is the name of an action, not a credential.
)

// The values of details.method of a login entry.
const (
	LoginMethodPassword = "password"
	LoginMethodUpstream = "upstream"
	LoginMethodPasskey  = "passkey"
)

// The reasons of a denied entry.
const (
	ReasonRefreshTokenReuse = "refresh_token_reuse" //nolint:gosec // G101: This is the name of a reason, not a credential.
	ReasonMFAFailed         = "mfa_failed"
	ReasonBadCredentials    = "bad_credentials"
)

// asClient returns a context with the authenticated client as the principal.
// The audit writer then takes the client as the actor of the entry. A use case
// calls it only after the client authentication works, or after the code or the
// refresh token verified the client.
func asClient(ctx context.Context, id string, typ auth.PrincipalType) context.Context {
	return auth.ContextWithPrincipal(ctx, auth.Principal{ID: id, Type: typ})
}

// entryAuditor writes an audit entry in its own short transaction. A token
// path that has no transaction uses it.
type entryAuditor struct {
	tx  transaction.Transactor
	w   audit.Writer
	log *slog.Logger
}

// ready reports whether the auditor can write.
func (a entryAuditor) ready() bool { return a.tx != nil && a.w != nil }

// success writes an entry with the result success. An error means that the
// caller must not give the result to the requester.
func (a entryAuditor) success(ctx context.Context, name string, at time.Time, action, targetType, targetID string, details map[string]any) error {
	if !a.ready() {
		return ErrNoAuditWriter
	}
	return a.tx.WithinTx(ctx, func(ctx context.Context) error {
		return writeAudit(ctx, a.w, at, action, targetType, targetID, details)
	}, txName(name))
}

// denied writes an entry with the result denied. A writer error is logged and
// does not change the response, because the request changed nothing. The log
// record has the action and the reason only.
func (a entryAuditor) denied(ctx context.Context, name string, at time.Time, action, targetType, targetID, reason string, details map[string]any) {
	d := make(map[string]any, len(details)+1)
	for k, v := range details {
		d[k] = v
	}
	d["reason"] = reason
	e := audit.Entry{Action: action, Result: audit.Denied, Time: at, Details: d}
	if targetID != "" {
		e.Target = &audit.Target{Type: targetType, ID: targetID}
	}
	var err error
	if !a.ready() {
		err = ErrNoAuditWriter
	} else {
		err = a.tx.WithinTx(ctx, func(ctx context.Context) error { return a.w.Write(ctx, e) }, txName(name))
	}
	if err != nil {
		a.log.ErrorContext(ctx, "identity.audit.failed", "event", "identity.audit.failed", "action", action, "reason", reason)
	}
}

// deniedCode returns the OAuth error code of a token request failure that gets
// a denied entry (decision D4). It returns false for a request that fails the
// validation, for a rate limit, and for a server error.
func deniedCode(err error) (string, bool) {
	oe, ok := apperrors.AsOAuthError(err)
	if !ok || oe.RateLimited {
		return "", false
	}
	switch oe.Code {
	case apperrors.OAuthInvalidClient, apperrors.OAuthInvalidGrant, apperrors.OAuthUnauthorizedClient, apperrors.OAuthInvalidScope:
		return oe.Code, true
	}
	return "", false
}

// tokenAuditError maps the error of the audit entry of a token issue to the
// OAuth error temporarily_unavailable. The response is 503 and has no token.
func tokenAuditError(err error) error {
	return apperrors.NewOAuthError(apperrors.OAuthTemporarilyUnavailable, "The service is not available. Try again.", err)
}

// loginDetails are the details of a login entry. The details never have the
// email.
func loginDetails(method, mfaMethod string) map[string]any {
	d := map[string]any{"method": method}
	if mfaMethod != "" {
		d["mfa"] = mfaMethod
	}
	return d
}

// writeLoginSuccess writes the success entry of a login. The user is the
// principal, because all steps of the login worked (decision D9). It must run
// in the transaction that makes the session.
func writeLoginSuccess(ctx context.Context, w audit.Writer, at time.Time, userID, method, mfaMethod string) error {
	return writeAudit(asUser(ctx, userID), w, at, ActionSessionLogin, targetUser, userID, loginDetails(method, mfaMethod))
}

// withLoginEntry runs fn, which makes the session, and writes the success entry
// of the login in the same transaction. A writer error stops the login.
func withLoginEntry(ctx context.Context, tx transaction.Transactor, w audit.Writer, at time.Time, userID, method, mfaMethod, name string, fn func(ctx context.Context) error) error {
	if tx == nil || w == nil {
		return ErrNoAuditWriter
	}
	return tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := fn(ctx); err != nil {
			return err
		}
		return writeLoginSuccess(ctx, w, at, userID, method, mfaMethod)
	}, txName(name))
}

// loginDenied writes the denied entry of a failed login or a failed second
// factor. The actor is the service identity, because the user is not verified.
// The target is the user only when the user is known. A writer error is logged
// and does not change the result of the login.
func loginDenied(ctx context.Context, tx transaction.Transactor, w audit.Writer, log *slog.Logger, at time.Time, userID, method, mfaMethod, reason string) {
	if log == nil {
		log = slog.Default()
	}
	entryAuditor{tx: tx, w: w, log: log}.denied(ctx, "audit_login_denied", at, ActionSessionLogin, targetUser, userID, reason, loginDetails(method, mfaMethod))
}

// The values of details.mfa of a login entry.
const (
	mfaTOTP     = "totp"
	mfaRecovery = "recovery_code"
	mfaPasskey  = "passkey"
)

// firstFactorMethod returns the details.method of the pending login: upstream
// for a login with a provider, else password.
func firstFactorMethod(p domain.PendingLogin) string {
	if p.Provider != "" {
		return LoginMethodUpstream
	}
	return LoginMethodPassword
}

// mfaMethodName returns the details.mfa value of the AMR value of a code.
func mfaMethodName(amr string) string {
	if amr == domain.AMRRecovery {
		return mfaRecovery
	}
	return mfaTOTP
}
