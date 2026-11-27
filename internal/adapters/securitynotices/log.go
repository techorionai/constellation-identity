// Package securitynotices holds the adapter of the port securitynotices. It
// writes one structured log record for each notice, because the service has no
// channel to the user yet.
package securitynotices

import (
	"context"
	"log/slog"

	"github.com/techorionai/constellation-identity/internal/ports/securitynotices"
)

// LogOnly writes a log record for each notice. A record has no secret, no
// code, and no email.
type LogOnly struct{ log *slog.Logger }

var _ securitynotices.Notices = (*LogOnly)(nil)

// NewLogOnly makes the adapter. A nil logger gives the default logger.
func NewLogOnly(log *slog.Logger) *LogOnly {
	if log == nil {
		log = slog.Default()
	}
	return &LogOnly{log: log}
}

// NotifyUser writes the record identity.security_notice.
func (l *LogOnly) NotifyUser(ctx context.Context, n securitynotices.Notice) error {
	l.log.InfoContext(ctx, "identity.security_notice", "event", "identity.security_notice", "kind", n.Kind,
		"target_user_id", n.TargetUserID, "at", n.At)
	return nil
}
