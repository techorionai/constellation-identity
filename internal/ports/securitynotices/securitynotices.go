// Package securitynotices is the port of the security notices of the service.
// The service has no channel to the user yet. The first adapter writes a log
// record for each call. Later work replaces the adapter and does not change
// the commands. The audit entries are not in this port. A command writes them
// with the audit writer of platform-go, in the transaction of the change.
package securitynotices

import (
	"context"
	"time"
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

// Notice is a security notice for a user.
type Notice struct {
	Kind         string
	TargetUserID string
	At           time.Time
}

// Notices sends security notices.
type Notices interface {
	// NotifyUser sends one security notice to the user.
	NotifyUser(ctx context.Context, n Notice) error
}
