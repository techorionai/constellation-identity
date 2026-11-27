package testserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/resources/test/containers"
	valkeygo "github.com/valkey-io/valkey-go"
)

// AuditStreamKey is the Valkey key of the audit stream of the identity service.
const AuditStreamKey = "audit.stream:identity"

// AuditRecord is one audit entry that a test reads from the audit stream. The
// reader ignores the members of the envelope and of data that it does not know.
type AuditRecord struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Source          string `json:"source"`
	SpecVersion     string `json:"specversion"`
	Time            string `json:"time"`
	DataContentType string `json:"datacontenttype"`
	Actor           string `json:"actor"`
	ActorType       string `json:"actortype"`
	Act             string `json:"act"`
	Data            struct {
		Action string `json:"action"`
		Result string `json:"result"`
		Target *struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"target"`
		Summary   string         `json:"summary"`
		Details   map[string]any `json:"details"`
		RequestID string         `json:"requestId"`
		IPAddress string         `json:"ipAddress"`
		UserAgent string         `json:"userAgent"`
	} `json:"data"`
	// Raw is the JSON text of the entry.
	Raw string `json:"-"`
}

// AuditReader reads audit.stream:identity with a Valkey user that has the audit
// reader selectors.
type AuditReader struct {
	c valkeygo.Client
}

// NewAuditReader makes a reader. The Valkey client closes at the end of the test.
func (e *Env) NewAuditReader(t testing.TB) *AuditReader {
	t.Helper()
	user, password := e.VK.NewACLUser(t, "auditreader", containers.ValkeyACLAuditReader())
	c, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress: []string{e.VK.Address()}, Username: user, Password: password.Reveal(), DisableCache: true,
	})
	if err != nil {
		t.Fatalf("testserver: audit reader: %v", err)
	}
	t.Cleanup(c.Close)
	return &AuditReader{c: c}
}

// All returns all entries of the stream in the order of the stream. A stream
// that does not exist gives no entries.
func (r *AuditReader) All(t testing.TB) []AuditRecord {
	t.Helper()
	entries, err := r.c.Do(context.Background(), r.c.B().Xrange().Key(AuditStreamKey).Start("-").End("+").Build()).AsXRange()
	if err != nil {
		if valkeygo.IsValkeyNil(err) {
			return nil
		}
		t.Fatalf("testserver: read the audit stream: %v", err)
	}
	var out []AuditRecord
	for _, e := range entries {
		var rec AuditRecord
		raw := e.FieldValues["event"]
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			t.Fatalf("testserver: audit entry is not JSON: %v", err)
		}
		rec.Raw = raw
		out = append(out, rec)
	}
	return out
}

// Find returns the entries with the action.
func (r *AuditReader) Find(t testing.TB, action string) []AuditRecord {
	t.Helper()
	var out []AuditRecord
	for _, rec := range r.All(t) {
		if rec.Data.Action == action {
			out = append(out, rec)
		}
	}
	return out
}

// Wait polls the stream for 10 seconds until match accepts at least n entries.
// It returns the accepted entries. It fails the test at the end of the time.
func (r *AuditReader) Wait(t testing.TB, n int, match func(AuditRecord) bool) []AuditRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var got []AuditRecord
		for _, rec := range r.All(t) {
			if match(rec) {
				got = append(got, rec)
			}
		}
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("testserver: %d audit entries matched, want %d", len(got), n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// WaitAuditRelayed waits for up to 10 seconds until the relay of the server
// moved all rows of the audit outbox to the audit stream.
func (s *Server) WaitAuditRelayed(t testing.TB) {
	t.Helper()
	pool := s.Pool(t)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM platform_audit_outbox WHERE published_at IS NULL`).Scan(&n); err != nil {
			t.Fatalf("testserver: count the unpublished audit rows: %v", err)
		}
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("testserver: %d audit rows are not published", n)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
