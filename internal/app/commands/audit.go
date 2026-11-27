package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/techorionai/constellation-platform-go/audit"
	"github.com/techorionai/constellation-platform-go/auth"
	"github.com/techorionai/constellation-platform-go/transaction"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
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
