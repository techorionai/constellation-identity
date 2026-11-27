//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
	swa "github.com/techorionai/constellation-identity/resources/test/webauthn"
)

var lowerUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// adminID returns the ID of the first admin of the fixture.
func (f *fixture) adminID() string {
	f.t.Helper()
	var id string
	if err := f.a.Pool(f.t).QueryRow(ctx, `SELECT id FROM users WHERE email = 'admin@example.com'`).Scan(&id); err != nil {
		f.t.Fatalf("admin ID: %v", err)
	}
	return id
}

// auditFor waits for n entries with the action and the target ID.
func (f *fixture) auditFor(n int, action, targetID string) []testserver.AuditRecord {
	f.t.Helper()
	f.a.WaitAuditRelayed(f.t)
	return f.a.audit.Wait(f.t, n, func(r testserver.AuditRecord) bool {
		return r.Data.Action == action && (targetID == "" || (r.Data.Target != nil && r.Data.Target.ID == targetID))
	})
}

// TestIssue25Integration is the integration test of the audit entries of the
// identity service. The tests use PostgreSQL and Valkey. A test reader reads
// audit.stream:identity with the audit reader ACL.
func TestIssue25Integration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h)
	admin := f.adminToken(apiAdminScopes)
	adminUser := f.adminID()
	var tokenValues []string

	// I1: the startup on a new database makes the audit outbox and its migrations table.
	t.Run("I1_startup_tables", func(t *testing.T) {
		if n := f.countWhere(`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('platform_audit_outbox', 'platform_audit_outbox_schema_migrations')`); n != 2 {
			t.Fatalf("tables = %d, want 2", n)
		}
		if n := f.countWhere(`SELECT count(*) FROM information_schema.tables WHERE table_name = 'platform_outbox'`); n != 0 {
			t.Fatal("the identity service runs no events outbox in this issue")
		}
	})

	// I2: an admin updates a user. One entry is on the audit stream.
	t.Run("I2_admin_update_user", func(t *testing.T) {
		id := f.newUser(admin, "i2@example.com", userPassword)
		body, _ := json.Marshal(map[string]string{"name": "I2 renamed"})
		resp, b := f.a.DoWith(t, http.MethodPatch, "/v1/users/"+id, admin, string(body), map[string]string{"User-Agent": "audit-test/1.0"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("update: %d %s", resp.StatusCode, b)
		}
		got := f.auditFor(1, "identity:user:update", id)
		e := got[0]
		if e.Actor != adminUser || e.ActorType != "user" || e.Data.Result != "success" || e.Data.Target.Type != "user" {
			t.Fatalf("entry = %s", e.Raw)
		}
		if e.Data.RequestID == "" || e.Data.IPAddress != "127.0.0.1" || e.Data.UserAgent != "audit-test/1.0" {
			t.Fatalf("request data of the entry = %s", e.Raw)
		}
		if !lowerUUID.MatchString(e.ID) || e.Type != "identity.audit.recorded" || e.Source != "/identity" || e.SpecVersion != "1.0" ||
			e.DataContentType != "application/json" {
			t.Fatalf("envelope = %s", e.Raw)
		}
		if fields, _ := e.Data.Details["fields"].([]any); len(fields) != 1 || fields[0] != "name" {
			t.Fatalf("details = %v", e.Data.Details)
		}
		// The set audit.streams has the app identity.
		vk := h.env.VK.Admin(t)
		ok, err := vk.Do(context.Background(), vk.B().Sismember().Key("audit.streams").Member("identity").Build()).AsBool()
		if err != nil || !ok {
			t.Fatalf("audit.streams has identity = %v, %v", ok, err)
		}
	})

	// I4: a PostgreSQL error at the audit insert gives 503 and no change.
	t.Run("I4_audit_failure_rolls_back", func(t *testing.T) {
		id := f.newUser(admin, "i4@example.com", userPassword)
		pool := f.a.Pool(t)
		for _, q := range []string{
			`CREATE FUNCTION i4_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit down'; END $$`,
			`CREATE TRIGGER i4_fail BEFORE INSERT ON platform_audit_outbox FOR EACH ROW EXECUTE FUNCTION i4_fail_audit()`,
		} {
			if _, err := pool.Exec(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
		resp, b := f.a.Do(t, http.MethodPut, "/v1/users/"+id+"/roles/demo:agent", admin, "")
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("assign: %d %s, want 503", resp.StatusCode, b)
		}
		if n := f.countWhere(`SELECT count(*) FROM user_roles WHERE user_id = $1 AND role = 'agent'`, id); n != 0 {
			t.Fatal("the role must not be assigned")
		}
		// The own manifest publish and the other changes fail the same way, and
		// the audit entry of a change that failed does not exist.
		if _, err := pool.Exec(ctx, `DROP TRIGGER i4_fail ON platform_audit_outbox`); err != nil {
			t.Fatal(err)
		}
		resp, b = f.a.Do(t, http.MethodPut, "/v1/users/"+id+"/roles/demo:agent", admin, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("assign after the repair: %d %s", resp.StatusCode, b)
		}
		got := f.auditFor(1, "identity:user_role:assign", id)
		if got[0].Data.Details["role"] != "demo:agent" {
			t.Fatalf("entry = %s", got[0].Raw)
		}
	})

	// I5: API token create and revoke by the user and by an admin. No entry has
	// the token text.
	t.Run("I5_api_tokens", func(t *testing.T) {
		id, access := f.apiUser(admin, "i5", "demo:agent")
		selfID, selfValue := f.mustCreate(access, "self", "demo:ticket:read")
		otherID, otherValue := f.mustCreate(access, "other", "demo:ticket:read")
		tokenValues = append(tokenValues, selfValue, otherValue)
		if resp, _ := f.a.Do(t, http.MethodDelete, "/v1/me/api-tokens/"+selfID, access, ""); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("self revoke: %d", resp.StatusCode)
		}
		if resp, b := f.a.Do(t, http.MethodDelete, "/v1/api-tokens/"+otherID, admin, ""); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("admin revoke: %d %s", resp.StatusCode, b)
		}
		creates := f.auditFor(2, "identity:api_token:create", "")
		revokes := f.auditFor(2, "identity:api_token:revoke", "")
		var self, other bool
		for _, r := range revokes {
			switch {
			case r.Data.Target.ID == selfID && r.Actor == id:
				self = true
			case r.Data.Target.ID == otherID && r.Actor == adminUser:
				other = true
			}
		}
		if !self || !other {
			t.Fatalf("revoke entries = %d, self %v, admin %v", len(revokes), self, other)
		}
		for _, r := range append(creates, revokes...) {
			for _, v := range tokenValues {
				if strings.Contains(r.Raw, v) || strings.Contains(r.Raw, strings.TrimPrefix(v, "cpat_")) {
					t.Fatalf("an entry has the text of a token: %s", r.Raw)
				}
			}
		}
	})

	// I6: a service publishes its manifest two times with the same content, then
	// with a change. Only the first publish and the change write entries.
	t.Run("I6_manifest_publish", func(t *testing.T) {
		tok := token(t, f.a.Server, f.serviceClient, "identity", "identity:manifest:publish")
		changed := manifestJSON(t, "demo", demoPerms, []string{"agent", "admin"}, map[string][]string{
			"agent": {"demo:ticket:read", "demo:ticket:write"},
			"admin": {"demo:ticket:read", "demo:ticket:write"},
		})
		for _, m := range []string{demoManifestJSON(t), demoManifestJSON(t), changed} {
			if resp, body := publish(t, f.a.Server, tok, "demo", m); resp.StatusCode != http.StatusOK {
				t.Fatalf("publish: %d %v", resp.StatusCode, body)
			}
		}
		f.a.WaitAuditRelayed(t)
		var mine []testserver.AuditRecord
		for _, r := range f.a.audit.Find(t, "identity:manifest:publish") {
			if r.Data.Target != nil && r.Data.Target.ID == "demo" {
				mine = append(mine, r)
			}
		}
		// The fixture made version 1. The same content writes no entry. The change makes version 2.
		if len(mine) < 2 {
			t.Fatalf("entries = %d, want 2", len(mine))
		}
		last := mine[len(mine)-1]
		if last.Actor != "demo" || last.ActorType != "service" || last.Data.Details["version"] != float64(len(mine)) {
			t.Fatalf("entries = %d, last = %s", len(mine), last.Raw)
		}
		if len(mine) != 2 {
			t.Fatalf("entries = %d, want 2 (two publishes of the same content write one entry)", len(mine))
		}
		// The own manifest at the start has the actor identity with the type service.
		var seenOwn bool
		for _, r := range f.a.audit.Find(t, "identity:manifest:publish") {
			if r.Data.Target != nil && r.Data.Target.ID == "identity" && r.Actor == "identity" && r.ActorType == "service" {
				seenOwn = true
			}
		}
		if !seenOwn {
			t.Fatal("no entry of the own manifest publish")
		}
	})

	// I7: a user token with no admin scope calls Users_update. The answer is 403
	// and one entry has the result denied.
	t.Run("I7_denied", func(t *testing.T) {
		id, access := f.apiUser(admin, "i7", "demo:agent")
		resp, _ := f.a.Do(t, http.MethodPatch, "/v1/users/"+id, access, `{"name":"x"}`)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		f.a.WaitAuditRelayed(t)
		var denied []testserver.AuditRecord
		for _, r := range f.a.audit.Find(t, "identity:user:update") {
			if r.Data.Result == "denied" && r.Actor == id {
				denied = append(denied, r)
			}
		}
		if len(denied) != 1 || denied[0].Data.Target != nil || denied[0].ActorType != "user" {
			t.Fatalf("denied entries = %d", len(denied))
		}
		if f.countWhere(`SELECT count(*) FROM users WHERE id = $1 AND name = 'x'`, id) != 0 {
			t.Fatal("the user must not change")
		}
	})

	// I10: a request with no User-Agent. The change works and the entry has no userAgent.
	t.Run("I10_no_user_agent", func(t *testing.T) {
		id := f.newUser(admin, "i10@example.com", userPassword)
		resp, b := f.a.DoWith(t, http.MethodPatch, "/v1/users/"+id, admin, `{"name":"I10 renamed"}`, map[string]string{"User-Agent": ""})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("update: %d %s", resp.StatusCode, b)
		}
		e := f.auditFor(1, "identity:user:update", id)[0]
		if e.Data.UserAgent != "" || e.Data.RequestID == "" {
			t.Fatalf("entry = %s", e.Raw)
		}
		if strings.Contains(e.Raw, "userAgent") {
			t.Fatalf("the entry must leave out userAgent: %s", e.Raw)
		}
	})

	// I11: a user renames a passkey on the account page. The actor is the user.
	t.Run("I11_page_rename_passkey", func(t *testing.T) {
		p := newFixture(t, h, mfaOptions()...)
		u := p.newPasskeyUserWith(p.adminToken(adminScopes), "i11@example.com", swa.ES256, "demo:agent")
		ids := p.passkeyIDs(u.id)
		resp, _ := u.web.PostForm(t, "/account/passkeys/"+ids[0]+"/rename", url.Values{"name": {"Renamed on the page"}})
		status(t, resp, http.StatusSeeOther, "rename on the page")
		e := p.auditFor(1, "identity:mfa:passkey_rename", u.id)[0]
		if e.Actor != u.id || e.ActorType != "user" || e.Data.Details["newName"] != "Renamed on the page" || e.Data.Details["oldName"] != "First" {
			t.Fatalf("entry = %s", e.Raw)
		}
	})

	// I12: more denied requests than the limit. The requests over the limit get
	// 429, and the number of denied entries is the limit.
	t.Run("I12_denied_rate_limit", func(t *testing.T) {
		g := newFixtureOn(t, h.start, testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketAdminDenied: {Limit: 3, Window: time.Hour}}))
		gadmin := g.adminToken(apiAdminScopes)
		id, access := g.apiUser(gadmin, "i12", "demo:agent")
		var ok, limited int
		for range 6 {
			resp, _ := g.a.Do(t, http.MethodPatch, "/v1/users/"+id, access, `{"name":"x"}`)
			switch resp.StatusCode {
			case http.StatusForbidden:
				ok++
			case http.StatusTooManyRequests:
				limited++
				if resp.Header.Get("Retry-After") == "" {
					t.Fatal("429 without Retry-After")
				}
			default:
				t.Fatalf("status = %d", resp.StatusCode)
			}
		}
		g.a.WaitAuditRelayed(t)
		var denied int
		for _, r := range g.a.audit.Find(t, "identity:user:update") {
			if r.Data.Result == "denied" && r.Actor == id {
				denied++
			}
		}
		if ok != 3 || limited != 3 || denied != 3 {
			t.Fatalf("403 = %d, 429 = %d, denied entries = %d, want 3 each", ok, limited, denied)
		}
	})

	// I8: the client IP follows the trusted proxy rule. The same address is the
	// key of the rate limit (the unit test of clientip checks the mapped IPv6
	// proxy address).
	t.Run("I8_forwarded_for", func(t *testing.T) {
		g := newFixtureOn(t, h.start, testserver.WithConfigure(func(c *config.Config) { c.HTTP.TrustedProxies = []string{"127.0.0.0/8", "::1/128"} }))
		gadmin := g.adminToken(apiAdminScopes)
		id := g.newUser(gadmin, "i8@example.com", userPassword)
		resp, b := g.a.DoWith(t, http.MethodPatch, "/v1/users/"+id, gadmin, `{"name":"I8 one"}`, map[string]string{"X-Forwarded-For": "203.0.113.9"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("update: %d %s", resp.StatusCode, b)
		}
		trusted := g.auditFor(1, "identity:user:update", id)[0]
		if trusted.Data.IPAddress != "203.0.113.9" {
			t.Fatalf("trusted proxy: ipAddress = %q, want 203.0.113.9", trusted.Data.IPAddress)
		}
		// A bad value in the header is not reliable. The address is the proxy.
		if resp, b = g.a.DoWith(t, http.MethodPatch, "/v1/users/"+id, gadmin, `{"name":"I8 two"}`, map[string]string{"X-Forwarded-For": "not-an-ip"}); resp.StatusCode != http.StatusOK {
			t.Fatalf("update: %d %s", resp.StatusCode, b)
		}
		got := g.auditFor(2, "identity:user:update", id)
		if got[1].Data.IPAddress != "127.0.0.1" {
			t.Fatalf("bad header: ipAddress = %q, want 127.0.0.1", got[1].Data.IPAddress)
		}
		// The server of the fixture f trusts no proxy. It ignores the header.
		id2 := f.newUser(admin, "i8b@example.com", userPassword)
		if resp, b = f.a.DoWith(t, http.MethodPatch, "/v1/users/"+id2, admin, `{"name":"I8 three"}`, map[string]string{"X-Forwarded-For": "203.0.113.9"}); resp.StatusCode != http.StatusOK {
			t.Fatalf("update: %d %s", resp.StatusCode, b)
		}
		if e := f.auditFor(1, "identity:user:update", id2)[0]; e.Data.IPAddress != "127.0.0.1" {
			t.Fatalf("untrusted: ipAddress = %q, want 127.0.0.1", e.Data.IPAddress)
		}
	})

	// I9: no log record is an audit record. No log record has the token of I5 or
	// an email address of an audit entry.
	t.Run("I9_logs", func(t *testing.T) {
		for _, r := range f.a.logs.Records(t) {
			if r["msg"] == "identity.audit" || r["msg"] == "identity.audit.failed" {
				t.Fatalf("log record = %v", r)
			}
		}
		raw := f.a.logs.Text()
		for _, v := range tokenValues {
			if strings.Contains(raw, v) {
				t.Fatal("a log record has the text of a token")
			}
		}
	})

}
