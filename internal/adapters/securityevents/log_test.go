package securityevents_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/techorionai/constellation-identity/internal/adapters/securityevents"
	port "github.com/techorionai/constellation-identity/internal/ports/securityevents"
)

// U25: one audit call and one notice call give one log record each, with the
// fields of the call and no other data.
func TestU25_LogOnly(t *testing.T) {
	var buf bytes.Buffer
	l := securityevents.NewLogOnly(slog.New(slog.NewJSONHandler(&buf, nil)))
	at := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	if err := l.RecordAudit(context.Background(), port.AuditEntry{
		Action: port.ActionMfaReset, Actor: "admin-1", TargetUserID: "user-1", Result: port.ResultSuccess, At: at,
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.NotifyUser(context.Background(), port.Notice{Kind: port.NoticeMfaReset, TargetUserID: "user-1", At: at}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("records = %d, want 2", len(lines))
	}
	var audit, notice map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &audit); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &notice); err != nil {
		t.Fatal(err)
	}
	if audit["msg"] != "identity.audit" || audit["action"] != "identity:mfa:reset" || audit["actor"] != "admin-1" ||
		audit["target_user_id"] != "user-1" || audit["result"] != "success" {
		t.Fatalf("audit = %v", audit)
	}
	if notice["msg"] != "identity.security_notice" || notice["kind"] != "mfa_reset" || notice["target_user_id"] != "user-1" {
		t.Fatalf("notice = %v", notice)
	}
	if strings.Contains(buf.String(), "@") {
		t.Fatal("a record must not have an email")
	}
}
