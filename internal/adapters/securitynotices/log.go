// Package securityevents holds the adapter of the port securityevents. It
// writes one structured log record for each call, because the service has no
// audit store and no channel to the user yet.
package securityevents

import (
	"context"
	"log/slog"

	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
)

// LogOnly writes a log record for each audit entry and each notice. A record
// has no secret, no code, and no email.
type LogOnly struct{ log *slog.Logger }

var _ securityevents.Events = (*LogOnly)(nil)

// NewLogOnly makes the adapter. A nil logger gives the default logger.
func NewLogOnly(log *slog.Logger) *LogOnly {
	if log == nil {
		log = slog.Default()
	}
	return &LogOnly{log: log}
}

// RecordAudit writes the record identity.audit.
func (l *LogOnly) RecordAudit(ctx context.Context, e securityevents.AuditEntry) error {
	attrs := []any{"event", "identity.audit", "action", e.Action, "actor", e.Actor,
		"target_user_id", e.TargetUserID, "result", e.Result, "at", e.At}
	if len(e.Changes) > 0 {
		attrs = append(attrs, "changes", e.Changes)
	}
	l.log.InfoContext(ctx, "identity.audit", attrs...)
	return nil
}

// NotifyUser writes the record identity.security_notice.
func (l *LogOnly) NotifyUser(ctx context.Context, n securityevents.Notice) error {
	l.log.InfoContext(ctx, "identity.security_notice", "event", "identity.security_notice", "kind", n.Kind,
		"target_user_id", n.TargetUserID, "at", n.At)
	return nil
}
