// Package securityevents is the port of the audit entries and the security
// notices of the service. The service has no audit store and no channel to the
// user yet. The first adapter writes a log record for each call. Later work
// replaces the adapter and does not change the commands.
package securityevents

import (
	"context"
	"time"
)

// The actions of the audit entries.
const (
	ActionTotpRemove = "identity:mfa:totp_remove"
	ActionMfaReset   = "identity:mfa:reset"
	// ActionPasskeyAdd, ActionPasskeyRemove, and ActionPasskeyRename are the
	// actions of the passkey changes.
	ActionPasskeyAdd    = "identity:mfa:passkey_add"    //nolint:gosec // G101: This is the name of an action, not a credential.
	ActionPasskeyRemove = "identity:mfa:passkey_remove" //nolint:gosec // G101: This is the name of an action, not a credential.
	ActionPasskeyRename = "identity:mfa:passkey_rename" //nolint:gosec // G101: This is the name of an action, not a credential.
	// ActionIdentityLinkAdd and ActionIdentityLinkRemove are the actions of the
	// changes of the upstream links.
	ActionIdentityLinkAdd    = "identity:identity_link:add"
	ActionIdentityLinkRemove = "identity:identity_link:remove"
	// ActionPasswordSet is the action of the first password of a user.
	ActionPasswordSet = "identity:password:set"
)

// The kinds of the security notices.
const (
	NoticeTotpRemoved = "mfa_totp_removed"
	NoticeMfaReset    = "mfa_reset"
	// NoticePasskeyAdded and NoticePasskeyRemoved tell the user about a change of the passkeys.
	NoticePasskeyAdded   = "mfa_passkey_added"   //nolint:gosec // G101: This is the name of a notice, not a credential.
	NoticePasskeyRemoved = "mfa_passkey_removed" //nolint:gosec // G101: This is the name of a notice, not a credential.
	// NoticeIdentityLinkAdded and NoticeIdentityLinkRemoved tell the user about
	// a change of the upstream links.
	NoticeIdentityLinkAdded   = "identity_link_added"
	NoticeIdentityLinkRemoved = "identity_link_removed"
	// NoticePasswordSet tells the user that a password was set.
	NoticePasswordSet = "password_set"
	// NoticeMfaLimited means a limit of second factor failures is reached.
	// Someone can know the password of the user.
	NoticeMfaLimited = "mfa_attempts_limited"
)

// ResultSuccess is the result of an action that worked.
const ResultSuccess = "success"

// ActorCLI is the actor of a change that the operator makes with a subcommand.
const ActorCLI = "cli"

// AuditEntry is one audit entry.
type AuditEntry struct {
	Action string
	// Actor is the ID of the principal that did the action, or ActorCLI.
	Actor string
	// TargetUserID is the user that the action changed.
	TargetUserID string
	Result       string
	At           time.Time
	// Changes is a short summary of the change, for example the old name and the
	// new name. It has no secret. It can be empty.
	Changes map[string]string
}

// Notice is a security notice for a user.
type Notice struct {
	Kind         string
	TargetUserID string
	At           time.Time
}

// Events records audit entries and sends security notices.
type Events interface {
	// RecordAudit writes one audit entry.
	RecordAudit(ctx context.Context, e AuditEntry) error
	// NotifyUser sends one security notice to the user.
	NotifyUser(ctx context.Context, n Notice) error
}
