package securitynotices_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/adapters/securitynotices"
	port "github.com/techorionai/constellation-identity/internal/ports/securitynotices"
)

// U1 of issue 25: the notices adapter writes identity.security_notice with no
// email, and it writes no identity.audit record.
func TestIssue25_U1_LogOnly(t *testing.T) {
	var buf bytes.Buffer
	l := securitynotices.NewLogOnly(slog.New(slog.NewJSONHandler(&buf, nil)))
	at := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	if err := l.NotifyUser(context.Background(), port.Notice{Kind: port.NoticeMfaReset, TargetUserID: "user-1", At: at}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("records = %d, want 1", len(lines))
	}
	var notice map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &notice); err != nil {
		t.Fatal(err)
	}
	if notice["msg"] != "identity.security_notice" || notice["kind"] != "mfa_reset" || notice["target_user_id"] != "user-1" {
		t.Fatalf("notice = %v", notice)
	}
	if strings.Contains(buf.String(), "@") || strings.Contains(buf.String(), "identity.audit") {
		t.Fatal("a record must not have an email or an audit record")
	}
}
