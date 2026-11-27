package commands

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// Issue29_U10: a denied login entry does not go through the token gate.
func TestIssue29_U10_LoginDeniedNotGated(t *testing.T) {
	ev := &mock.Events{}
	for range 50 {
		loginDenied(context.Background(), mock.Tx{}, ev, slog.New(slog.DiscardHandler), time.Unix(0, 0), "u1", LoginMethodPassword, "", ReasonBadCredentials)
	}
	if len(ev.Audits) != 50 {
		t.Fatalf("entries = %d, want 50", len(ev.Audits))
	}
}
