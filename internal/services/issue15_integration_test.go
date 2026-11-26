//go:build integration

package services_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/techorionai/constellation-platform-go/resources/test/containers"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/migrations"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
	swa "github.com/techorionai/constellation-identity/resources/test/webauthn"
)

// recordsOf returns the log records with the message.
func recordsOf(t *testing.T, a *app, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range a.logs.Records(t) {
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

func auditsOf(t *testing.T, a *app, action string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range recordsOf(t, a, "identity.audit") {
		if r["action"] == action {
			out = append(out, r)
		}
	}
	return out
}

func noticesOf(t *testing.T, a *app, kind string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range recordsOf(t, a, "identity.security_notice") {
		if r["kind"] == kind {
			out = append(out, r)
		}
	}
	return out
}

// verificationCount returns the value of the counter identity.mfa.verifications
// for a method.
func verificationCount(t *testing.T, method string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := metricReader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if m.Name != "identity.mfa.verifications" || !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				if v, ok := dp.Attributes.Value("method"); ok && v.AsString() == method {
					total += dp.Value
				}
			}
		}
	}
	return total
}

// errorOf reads the error code of a JSON answer of a passkey route.
func errorOf(m map[string]any) string {
	s, _ := m["error"].(string)
	return s
}

func methodsOf(t *testing.T, f *fixture, web *testserver.Web) string {
	t.Helper()
	var amr []string
	row := f.a.Pool(t).QueryRow(ctx, `SELECT amr FROM sessions WHERE token_hash = encode(sha256($1::bytea), 'hex')`, web.Cookie(pages.CookieName))
	if err := row.Scan(&amr); err != nil {
		t.Fatalf("session methods: %v", err)
	}
	return strings.Join(amr, " ")
}

// I1: migration 0013 up and down. The previous version runs on the new schema.
func TestIssue15MigrationIntegration(t *testing.T) {
	env := testserver.NewEnv(t)
	u, _ := env.PG.NewDatabase(t)
	pool, err := pgxpool.New(ctx, string(u))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrations(t, pool, 1, 12)
	const userA = "00000000-0000-4000-8000-0000000000aa"
	const userB = "00000000-0000-4000-8000-0000000000ab"
	for _, id := range []string{userA, userB} {
		if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, name, status, created_at, updated_at) VALUES ($1, $2, 'M', 'active', now(), now())`, id, id+"@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	applyMigrations(t, pool, 13, 13)
	// The SQL of the previous version works on the new schema.
	for _, q := range []string{
		`SELECT id, email, name, status, password_hash, created_at, updated_at FROM users WHERE id = '` + userA + `'`,
		`UPDATE users SET name = 'N', updated_at = now() WHERE id = '` + userA + `'`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("old SQL: %v\n%s", err, q)
		}
	}
	insert := `INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, aaguid, backup_eligible, backup_state, name, created_at)
		VALUES ($1, $2, $3, '\x01', 0, '\x00', true, false, 'k', now())`
	if _, err := pool.Exec(ctx, insert, "00000000-0000-4000-8000-0000000000c1", userA, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, insert, "00000000-0000-4000-8000-0000000000c2", userB, []byte("one")); err == nil {
		t.Fatal("a credential ID of another user must fail")
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET webauthn_user_handle = '\x0102' WHERE id = $1`, userA); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET webauthn_user_handle = '\x0102' WHERE id = $1`, userB); err == nil {
		t.Fatal("a user handle of another user must fail")
	}
	// A user delete removes the passkeys.
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userA); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM webauthn_credentials`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows after the user delete: %d, %v", n, err)
	}
	down, err := migrations.Files.ReadFile("0013_passkeys.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'webauthn_credentials'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tables after the down: %d, %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'webauthn_user_handle'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("columns after the down: %d, %v", n, err)
	}
}

func TestIssue15Integration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h, mfaOptions()...)
	const demoRole = "demo:agent"

	// I2: the registration with ES256 and with EdDSA.
	t.Run("I2_registration", func(t *testing.T) {
		for i, alg := range []swa.Algorithm{swa.ES256, swa.EdDSA} {
			u := f.newPasskeyUser("i2-"+string(rune('a'+i))+"@example.com", alg, demoRole)
			var name string
			var pub, aaguid []byte
			var be, bs bool
			var last *time.Time
			row := f.a.Pool(t).QueryRow(ctx, `SELECT name, public_key, backup_eligible, backup_state, last_used_at, aaguid FROM webauthn_credentials WHERE user_id = $1`, u.id)
			if err := row.Scan(&name, &pub, &be, &bs, &last, &aaguid); err != nil {
				t.Fatal(err)
			}
			if name != "First" || len(pub) == 0 || !be || !bs || last != nil {
				t.Fatalf("row: name %q key %d be %v bs %v last %v", name, len(pub), be, bs, last)
			}
			if f.countWhere(`SELECT count(*) FROM users WHERE id = $1 AND octet_length(webauthn_user_handle) = 32`, u.id) != 1 {
				t.Fatal("the user handle must have 32 bytes")
			}
			if got := methodsOf(t, f, u.web); got != "pwd hwk user mfa" {
				t.Fatalf("the session after the registration = %q", got)
			}
			tok := f.passkeyToken(u, passkeyScope)
			resp, m := f.api(tok, http.MethodGet, "/v1/me/passkeys", nil)
			status(t, resp, http.StatusOK, "MePasskeys_list")
			items, _ := m["items"].([]any)
			if len(items) != 1 {
				t.Fatalf("list = %v", m)
			}
			item := items[0].(map[string]any)
			if item["name"] != "First" || item["synced"] != true || item["createdAt"] == nil {
				t.Fatalf("item = %v", item)
			}
			// The login made last_used_at, but the list of a token before it had none. Here it is set.
			if _, has := item["lastUsedAt"]; !has {
				t.Fatalf("lastUsedAt must be set after the login: %v", item)
			}
			for _, key := range []string{"credentialId", "publicKey", "signCount", "userHandle", "aaguid"} {
				if _, has := item[key]; has {
					t.Fatalf("the item has %s", key)
				}
			}
		}
		if verificationCount(t, "hwk") < 0 {
			t.Fatal("unreachable")
		}
	})

	// I3: a stale session cannot register a passkey.
	t.Run("I3_stale_session", func(t *testing.T) {
		id := f.newUser(f.adminToken(adminScopes), "i3@example.com", userPassword, demoRole)
		web := f.a.NewWeb()
		f.passwordLogin(web, "i3@example.com", userPassword, "/login/done")
		f.advance(6 * time.Minute)
		resp, m, _ := f.jsonPost(web, "/account/passkeys/options", []byte(`{"name":"late"}`))
		status(t, resp, http.StatusUnauthorized, "options with a stale session")
		if errorOf(m) != "login_required" || !strings.HasPrefix(m["redirect"].(string), "/login?return_to=") {
			t.Fatalf("answer = %v", m)
		}
		resp, _ = web.Get(t, "/account/passkeys")
		status(t, resp, http.StatusSeeOther, "GET /account/passkeys with a stale session")
		if !strings.HasPrefix(resp.Header.Get("Location"), "/login?return_to=") {
			t.Fatalf("Location = %q", resp.Header.Get("Location"))
		}
		if f.passkeyRows(id) != 0 {
			t.Fatal("no row may exist")
		}
	})

	// I4: a response with a wrong origin, a wrong RP ID hash, or no UV flag is refused.
	t.Run("I4_bad_registration_responses", func(t *testing.T) {
		id := f.newUser(f.adminToken(adminScopes), "i4@example.com", userPassword, demoRole)
		web := f.a.NewWeb()
		f.passwordLogin(web, "i4@example.com", userPassword, "/login/done")
		for name, opt := range map[string]swa.CallOption{
			"origin": swa.WithOrigin("https://evil.example"), "rp id hash": swa.WithRPID("evil.example"), "no uv": swa.WithUV(false),
		} {
			resp, m := f.registerPasskey(web, f.newAuthenticator(swa.ES256), "bad", opt)
			if resp.StatusCode != http.StatusUnauthorized || errorOf(m) != "invalid_passkey" {
				t.Fatalf("%s: %d %v", name, resp.StatusCode, m)
			}
		}
		if f.passkeyRows(id) != 0 {
			t.Fatal("no row may exist")
		}
	})

	// I5: the same credential two times, and a credential ID of another user.
	t.Run("I5_duplicate_credential", func(t *testing.T) {
		a := f.newPasskeyUser("i5a@example.com", swa.ES256, demoRole)
		b := f.newPasskeyUser("i5b@example.com", swa.ES256, demoRole)
		// The finish step of the same response again: the state is gone.
		req, _ := json.Marshal(map[string]string{"name": "again"})
		_, _, raw := f.jsonPost(a.web, "/account/passkeys/options", req)
		response := a.key.Create(t, raw)
		resp, _, _ := f.jsonPost(a.web, "/account/passkeys/finish", response)
		status(t, resp, http.StatusOK, "first finish")
		resp, m, _ := f.jsonPost(a.web, "/account/passkeys/finish", response)
		if resp.StatusCode != http.StatusBadRequest || errorOf(m) != "expired" {
			t.Fatalf("second finish: %d %v", resp.StatusCode, m)
		}
		// A credential ID that user A registered.
		before := f.passkeyRows(b.id)
		resp, m = f.registerPasskey(b.web, f.newAuthenticator(swa.ES256), "taken", swa.WithCredentialID(a.key.Creds[0].ID))
		if resp.StatusCode != http.StatusUnauthorized || errorOf(m) != "invalid_passkey" {
			t.Fatalf("credential of another user: %d %v", resp.StatusCode, m)
		}
		if f.passkeyRows(b.id) != before {
			t.Fatal("no new row may exist")
		}
		// The credential of the same user again.
		resp, m = f.registerPasskey(a.web, f.newAuthenticator(swa.ES256), "same", swa.WithCredentialID(a.key.Creds[0].ID))
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("the same credential again: %d %v", resp.StatusCode, m)
		}
	})

	// I6: the code flow with a passkey and no password.
	t.Run("I6_passkey_login", func(t *testing.T) {
		u := f.newPasskeyUser("i6@example.com", swa.ES256, demoRole)
		runs, logins := passwordRuns(t), loginCount(t, "ok")+loginCount(t, "bad_credentials")+loginCount(t, "mfa_pending")
		tr := f.passkeyCodeFlow(f.a.NewWeb(), u.key, "admin-ui", adminRedirect, mfaScope, nil)
		if got := amrOf(t, tr.AccessToken); got != "hwk user mfa" {
			t.Fatalf("access token amr = %q", got)
		}
		if got := amrOf(t, tr.IDToken); got != "hwk user mfa" {
			t.Fatalf("ID token amr = %q", got)
		}
		if passwordRuns(t) != runs || loginCount(t, "ok")+loginCount(t, "bad_credentials")+loginCount(t, "mfa_pending") != logins {
			t.Fatal("a passkey login must not touch the password login")
		}
		if f.countWhere(`SELECT count(*) FROM webauthn_credentials WHERE user_id = $1 AND last_used_at IS NOT NULL AND sign_count = 1`, u.id) != 1 {
			t.Fatal("last_used_at and the sign count must be set")
		}
	})

	// I7: the same finish body two times.
	t.Run("I7_replay", func(t *testing.T) {
		u := f.newPasskeyUser("i7@example.com", swa.ES256, demoRole)
		web := f.a.NewWeb()
		resp, _, raw := f.jsonPost(web, "/login/passkey/options", []byte(`{}`))
		status(t, resp, http.StatusOK, "options")
		token := web.Cookie(pages.WebAuthnCookieName)
		response := u.key.Get(t, raw)
		resp, _, _ = f.jsonPost(web, "/login/passkey/finish", response)
		status(t, resp, http.StatusOK, "first finish")
		web.SetCookie(pages.WebAuthnCookieName, token)
		resp, m, _ := f.jsonPost(web, "/login/passkey/finish", response)
		if resp.StatusCode != http.StatusBadRequest || errorOf(m) != "expired" {
			t.Fatalf("second finish: %d %v", resp.StatusCode, m)
		}
	})

	// I8: the challenge of another browser.
	t.Run("I8_other_browser", func(t *testing.T) {
		u := f.newPasskeyUser("i8@example.com", swa.ES256, demoRole)
		webA, webB := f.a.NewWeb(), f.a.NewWeb()
		_, _, rawA := f.jsonPost(webA, "/login/passkey/options", []byte(`{}`))
		f.jsonPost(webB, "/login/passkey/options", []byte(`{}`))
		response := u.key.Get(t, rawA)
		resp, m, _ := f.jsonPost(webB, "/login/passkey/finish", response)
		if resp.StatusCode != http.StatusUnauthorized || errorOf(m) != "invalid_passkey" || webB.Cookie(pages.CookieName) != "" {
			t.Fatalf("response of another browser: %d %v", resp.StatusCode, m)
		}
	})

	// I9, I10: a user handle that does not fit, and a disabled user. The same text for all.
	t.Run("I9_I10_refusals", func(t *testing.T) {
		u := f.newPasskeyUser("i9@example.com", swa.ES256, demoRole)
		web := f.a.NewWeb()
		resp, m := f.passkeyLogin(web, u.key, "", swa.WithUserHandle([]byte("another user handle")))
		if resp.StatusCode != http.StatusUnauthorized || errorOf(m) != "invalid_passkey" {
			t.Fatalf("handle: %d %v", resp.StatusCode, m)
		}
		resp, m = f.passkeyLogin(web, u.key, "", swa.WithoutUserHandle())
		if resp.StatusCode != http.StatusUnauthorized || errorOf(m) != "invalid_passkey" {
			t.Fatalf("no handle: %d %v", resp.StatusCode, m)
		}
		if _, err := f.a.Pool(t).Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, u.id); err != nil {
			t.Fatal(err)
		}
		resp, m = f.passkeyLogin(web, u.key, "")
		if resp.StatusCode != http.StatusUnauthorized || errorOf(m) != "invalid_passkey" || web.Cookie(pages.CookieName) != "" {
			t.Fatalf("disabled user: %d %v", resp.StatusCode, m)
		}
		if _, err := f.a.Pool(t).Exec(ctx, `UPDATE users SET status = 'active' WHERE id = $1`, u.id); err != nil {
			t.Fatal(err)
		}
	})

	// I11: a cloned authenticator, and two parallel requests.
	t.Run("I11_clone", func(t *testing.T) {
		u := f.newPasskeyUser("i11@example.com", swa.ES256, demoRole)
		web := f.a.NewWeb()
		if resp, _ := f.passkeyLogin(web, u.key, "", swa.WithCount(7)); resp.StatusCode != http.StatusOK {
			t.Fatalf("count 7: %d", resp.StatusCode)
		}
		resp, m := f.passkeyLogin(f.a.NewWeb(), u.key, "", swa.WithCount(7))
		if resp.StatusCode != http.StatusUnauthorized || errorOf(m) != "invalid_passkey" {
			t.Fatalf("count 7 again: %d %v", resp.StatusCode, m)
		}
		if len(recordsOf(t, f.a, "identity.passkey.clone_warning")) == 0 {
			t.Fatal("no clone warning record")
		}
		// Two parallel finish requests with the count 8. One makes a session.
		var webs [2]*testserver.Web
		var bodies [2][]byte
		for i := range webs {
			webs[i] = f.a.NewWeb()
			_, _, raw := f.jsonPost(webs[i], "/login/passkey/options", []byte(`{}`))
			bodies[i] = u.key.Get(t, raw, swa.WithCount(8))
		}
		var wg sync.WaitGroup
		var codes [2]int
		for i := range webs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, _ := webs[i].PostJSON(t, "/login/passkey/finish", bodies[i])
				codes[i] = resp.StatusCode
			}()
		}
		wg.Wait()
		ok := 0
		for _, c := range codes {
			if c == http.StatusOK {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("parallel requests: %v, want exactly one 200", codes)
		}
	})

	// I12: the password, then a passkey as the second factor.
	t.Run("I12_second_factor", func(t *testing.T) {
		u := f.newPasskeyUser("i12@example.com", swa.ES256, demoRole)
		before := verificationCount(t, "hwk")
		web := f.a.NewWeb()
		p := testserver.NewPKCE(t)
		f.startMFALogin(web, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, p, nil), u.email, u.password)
		resp, body := web.Get(t, "/login/mfa")
		status(t, resp, http.StatusOK, "GET /login/mfa")
		for _, want := range []string{`data-passkey="second-factor"`, "Use a passkey", `src="/assets/passkey.js"`} {
			if !strings.Contains(string(body), want) {
				t.Fatalf("the page has no %q: %s", want, body)
			}
		}
		if strings.Contains(string(body), "recovery") || strings.Contains(string(body), `name="code"`) {
			t.Fatalf("a user with passkeys only has no code form and no recovery link: %s", body)
		}
		resp, _, raw := f.jsonPost(web, "/login/mfa/passkey/options", []byte(`{}`))
		status(t, resp, http.StatusOK, "second factor options")
		var o struct {
			PublicKey struct {
				Allow            []any  `json:"allowCredentials"`
				UserVerification string `json:"userVerification"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(raw, &o); err != nil || len(o.PublicKey.Allow) != 1 || o.PublicKey.UserVerification != "preferred" {
			t.Fatalf("options = %s", raw)
		}
		response := u.key.Get(t, raw)
		f.trackWebAuthn(raw, u.key)
		resp, m, _ := f.jsonPost(web, "/login/mfa/passkey/finish", response)
		status(t, resp, http.StatusOK, "second factor finish")
		next, _ := m["redirect"].(string)
		f.a.trackSession(web)
		resp, _ = web.Get(t, next)
		status(t, resp, http.StatusFound, "continue")
		tr := f.exchangeCode(testserver.Location(t, resp), p, "admin-ui", adminRedirect)
		if got := amrOf(t, tr.AccessToken); got != "pwd hwk user mfa" {
			t.Fatalf("amr = %q", got)
		}
		if verificationCount(t, "hwk") != before+1 {
			t.Fatalf("identity.mfa.verifications for hwk: %d, want %d", verificationCount(t, "hwk"), before+1)
		}
		// A security key with no UV is a valid second factor, with no method user.
		web2 := f.a.NewWeb()
		f.startMFALogin(web2, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, testserver.NewPKCE(t), nil), u.email, u.password)
		_, _, raw = f.jsonPost(web2, "/login/mfa/passkey/options", []byte(`{}`))
		resp, _, _ = f.jsonPost(web2, "/login/mfa/passkey/finish", u.key.Get(t, raw, swa.WithUV(false)))
		status(t, resp, http.StatusOK, "second factor with no UV")
		if got := methodsOf(t, f, web2); got != "pwd hwk mfa" {
			t.Fatalf("methods = %q", got)
		}
	})

	// I13: the password of user A and a passkey of user B.
	t.Run("I13_other_user", func(t *testing.T) {
		a := f.newPasskeyUser("i13a@example.com", swa.ES256, demoRole)
		b := f.newPasskeyUser("i13b@example.com", swa.ES256, demoRole)
		web := f.a.NewWeb()
		f.startMFALogin(web, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, testserver.NewPKCE(t), nil), a.email, a.password)
		_, _, raw := f.jsonPost(web, "/login/mfa/passkey/options", []byte(`{}`))
		response := b.key.Get(t, raw, swa.WithCredential(b.key.Creds[0]))
		resp, m, _ := f.jsonPost(web, "/login/mfa/passkey/finish", response)
		if resp.StatusCode != http.StatusUnauthorized || errorOf(m) != "invalid_passkey" {
			t.Fatalf("passkey of user B: %d %v", resp.StatusCode, m)
		}
		if f.countWhere(`SELECT count(*) FROM sessions WHERE user_id = $1 AND token_hash = encode(sha256($2::bytea), 'hex')`, a.id, web.Cookie(pages.CookieName)) != 0 {
			t.Fatal("no session may exist")
		}
	})

	// I15, I34: the removal and the rename of a passkey with the API.
	t.Run("I15_I34_api", func(t *testing.T) {
		u := f.newPasskeyUser("i15@example.com", swa.ES256, demoRole)
		if resp, m := f.registerPasskey(u.web, u.key, "Second"); resp.StatusCode != http.StatusOK {
			t.Fatalf("second passkey: %v", m)
		}
		ids := f.passkeyIDs(u.id)
		fresh := f.passkeyToken(u, passkeyScope)
		// I34: the rename needs a fresh MFA login.
		resp, m := f.apiRaw(fresh, http.MethodPatch, "/v1/me/passkeys/"+ids[0], `{"name":"Renamed key"}`)
		if resp.StatusCode != http.StatusOK || m["name"] != "Renamed key" {
			t.Fatalf("rename: %d %v", resp.StatusCode, m)
		}
		if len(auditsOf(t, f.a, "identity:mfa:passkey_rename")) == 0 {
			t.Fatal("no audit entry of the rename")
		}
		// A token with no mfa: a fresh password login.
		f.newUser(f.adminToken(adminScopes), "i15plain@example.com", userPassword, demoRole)
		plain, _ := f.login("i15plain@example.com", userPassword, "admin-ui", adminRedirect, passkeyScope)
		resp, m = f.apiRaw(plain.AccessToken, http.MethodPatch, "/v1/me/passkeys/"+ids[0], `{"name":"No MFA"}`)
		if resp.StatusCode != http.StatusUnauthorized || m["code"] != "reauthentication_required" ||
			!strings.Contains(resp.Header.Get("WWW-Authenticate"), "insufficient_user_authentication") {
			t.Fatalf("token with no mfa: %d %v %v", resp.StatusCode, m, resp.Header)
		}
		// The hosted rename form with a fresh session.
		resp, _ = u.web.PostForm(t, "/account/passkeys/"+ids[1]+"/rename", nameForm("Form name"))
		status(t, resp, http.StatusSeeOther, "rename form")
		if f.countWhere(`SELECT count(*) FROM webauthn_credentials WHERE id = $1 AND name = 'Form name'`, ids[1]) != 1 {
			t.Fatal("the form did not rename")
		}
		if len(auditsOf(t, f.a, "identity:mfa:passkey_rename")) < 2 {
			t.Fatal("the form needs an audit entry")
		}
		// An old token and an old session.
		f.advance(6 * time.Minute)
		resp, m = f.apiRaw(fresh, http.MethodPatch, "/v1/me/passkeys/"+ids[0], `{"name":"Late"}`)
		if resp.StatusCode != http.StatusUnauthorized || m["code"] != "reauthentication_required" {
			t.Fatalf("old token: %d %v", resp.StatusCode, m)
		}
		resp, _ = u.web.PostForm(t, "/account/passkeys/"+ids[1]+"/rename", nameForm("Late form"))
		status(t, resp, http.StatusSeeOther, "rename form with an old session")
		if !strings.HasPrefix(resp.Header.Get("Location"), "/login?return_to=") ||
			f.countWhere(`SELECT count(*) FROM webauthn_credentials WHERE id = $1 AND name = 'Form name'`, ids[1]) != 1 {
			t.Fatalf("old session: Location %q", resp.Header.Get("Location"))
		}
		resp, m = f.apiRaw(fresh, http.MethodDelete, "/v1/me/passkeys/"+ids[0], "")
		if resp.StatusCode != http.StatusUnauthorized || m["code"] != "reauthentication_required" {
			t.Fatalf("remove with an old token: %d %v", resp.StatusCode, m)
		}
		// I15: a fresh token removes the passkey. It writes the audit entry and the notice.
		fresh = f.passkeyToken(u, passkeyScope)
		before := len(noticesOf(t, f.a, "mfa_passkey_removed"))
		resp, _ = f.apiRaw(fresh, http.MethodDelete, "/v1/me/passkeys/"+ids[0], "")
		status(t, resp, http.StatusNoContent, "remove")
		if f.passkeyRows(u.id) != 1 || len(auditsOf(t, f.a, "identity:mfa:passkey_remove")) == 0 || len(noticesOf(t, f.a, "mfa_passkey_removed")) != before+1 {
			t.Fatal("the removal needs the row change, the audit entry, and the notice")
		}
	})

	// I22, I23, I24, I25: the scopes and the order of the checks.
	t.Run("I22_I25_order", func(t *testing.T) {
		u := f.newPasskeyUser("i22@example.com", swa.ES256, demoRole)
		other := f.newPasskeyUser("i22o@example.com", swa.ES256, demoRole)
		resp, _ := f.api(f.adminToken("identity:user:read"), http.MethodGet, "/v1/users/"+u.id+"/passkeys", nil)
		status(t, resp, http.StatusForbidden, "UserPasskeys_list with identity:user:read")
		reader := f.adminToken("identity:mfa:read")
		resp, m := f.api(reader, http.MethodGet, "/v1/users/"+u.id+"/passkeys", nil)
		if items, _ := m["items"].([]any); resp.StatusCode != http.StatusOK || len(items) != 1 {
			t.Fatalf("UserPasskeys_list: %d %v", resp.StatusCode, m)
		}
		resp, m = f.api(reader, http.MethodGet, "/v1/users/00000000-0000-4000-8000-0000000000ee/passkeys", nil)
		if resp.StatusCode != http.StatusNotFound || m["code"] != "user_not_found" {
			t.Fatalf("unknown user: %d %v", resp.StatusCode, m)
		}
		fresh := f.passkeyToken(u, passkeyScope)
		otherID := f.passkeyIDs(other.id)[0]
		unknown := "00000000-0000-4000-8000-0000000000ee"
		for _, c := range []struct{ method, id, body string }{
			{http.MethodPatch, otherID, `{"name":"x"}`}, {http.MethodDelete, otherID, ""},
			{http.MethodPatch, "abc", `{"name":"x"}`}, {http.MethodDelete, "abc", ""},
			{http.MethodPatch, unknown, `{"name":"a\nb"}`}, {http.MethodPatch, "abc", `{"name":"a\nb"}`},
		} {
			resp, m := f.apiRaw(fresh, c.method, "/v1/me/passkeys/"+c.id, c.body)
			if resp.StatusCode != http.StatusNotFound || m["code"] != "passkey_not_found" {
				t.Fatalf("%s %s: %d %v", c.method, c.id, resp.StatusCode, m)
			}
		}
		resp, m = f.apiRaw(fresh, http.MethodPatch, "/v1/me/passkeys/"+f.passkeyIDs(u.id)[0], `{"name":"a\nb"}`)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("bad name: %d %v", resp.StatusCode, m)
		}
		if f.passkeyRows(other.id) != 1 {
			t.Fatal("the passkey of another user must stay")
		}
	})

	// I26: the limit of 10 passkeys.
	t.Run("I26_limit", func(t *testing.T) {
		u := f.newPasskeyUser("i26@example.com", swa.ES256, demoRole)
		for i := 2; i <= 10; i++ {
			if resp, m := f.registerPasskey(u.web, u.key, "key "+string(rune('0'+i%10))); resp.StatusCode != http.StatusOK {
				t.Fatalf("registration %d: %d %v", i, resp.StatusCode, m)
			}
		}
		resp, m, _ := f.jsonPost(u.web, "/account/passkeys/options", []byte(`{"name":"eleven"}`))
		if resp.StatusCode != http.StatusConflict || errorOf(m) != "passkey_limit" {
			t.Fatalf("the eleventh: %d %v", resp.StatusCode, m)
		}
		if f.passkeyRows(u.id) != 10 {
			t.Fatalf("rows = %d", f.passkeyRows(u.id))
		}
	})

	// I27: a name that is not valid.
	t.Run("I27_names", func(t *testing.T) {
		u := f.newPasskeyUser("i27@example.com", swa.ES256, demoRole)
		resp, m, _ := f.jsonPost(u.web, "/account/passkeys/options", []byte(`{"name":" a"}`))
		if resp.StatusCode != http.StatusBadRequest || errorOf(m) != "invalid_name" || f.passkeyRows(u.id) != 1 {
			t.Fatalf("options: %d %v", resp.StatusCode, m)
		}
		id := f.passkeyIDs(u.id)[0]
		resp, body := u.web.PostForm(t, "/account/passkeys/"+id+"/rename", nameForm("a "))
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "The name must have 1 to 64 characters") ||
			f.countWhere(`SELECT count(*) FROM webauthn_credentials WHERE id = $1 AND name = 'First'`, id) != 1 {
			t.Fatalf("rename form: %d %s", resp.StatusCode, body)
		}
		// A passkey of another user and an ID that is not a UUID.
		resp, body = u.web.PostForm(t, "/account/passkeys/abc/rename", nameForm("x"))
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), "Passkey not found") {
			t.Fatalf("unknown passkey: %d %s", resp.StatusCode, body)
		}
	})

	// I28: the order and the cursor of the lists.
	t.Run("I28_cursor", func(t *testing.T) {
		u := f.newPasskeyUser("i28@example.com", swa.ES256, demoRole)
		for _, name := range []string{"two", "three"} {
			if resp, m := f.registerPasskey(u.web, u.key, name); resp.StatusCode != http.StatusOK {
				t.Fatalf("registration: %v", m)
			}
		}
		if f.countWhere(`SELECT count(DISTINCT created_at) FROM webauthn_credentials WHERE user_id = $1`, u.id) != 1 {
			t.Fatal("the test needs three passkeys with the same creation time")
		}
		want := f.passkeyIDs(u.id)
		if !slices.IsSorted(want) {
			t.Fatalf("ids = %v", want)
		}
		walk := func(tok, path string) []string {
			var got []string
			q := "?pageSize=2"
			for pages := 0; pages < 3; pages++ {
				resp, m := f.api(tok, http.MethodGet, path+q, nil)
				status(t, resp, http.StatusOK, path)
				for _, it := range m["items"].([]any) {
					got = append(got, it.(map[string]any)["id"].(string))
				}
				next, _ := m["nextPageToken"].(string)
				if next == "" {
					return got
				}
				q = "?pageSize=2&pageToken=" + url.QueryEscape(next)
			}
			t.Fatal("too many pages")
			return nil
		}
		if got := walk(f.passkeyToken(u, passkeyScope), "/v1/me/passkeys"); !slices.Equal(got, want) {
			t.Fatalf("MePasskeys_list = %v, want %v", got, want)
		}
		if got := walk(f.adminToken("identity:mfa:read"), "/v1/users/"+u.id+"/passkeys"); !slices.Equal(got, want) {
			t.Fatalf("UserPasskeys_list = %v, want %v", got, want)
		}
	})

	// I29: MfaStatus.
	t.Run("I29_status", func(t *testing.T) {
		u := f.newPasskeyUser("i29@example.com", swa.ES256, demoRole)
		st := f.mfaStatus(f.passkeyToken(u, mfaScope))
		if st["enabled"] != true || st["passkeys"] != float64(1) || st["required"] != false {
			t.Fatalf("status = %v", st)
		}
		f.newUser(f.adminToken(adminScopes), "i29b@example.com", userPassword, demoRole)
		tr, _ := f.login("i29b@example.com", userPassword, "admin-ui", adminRedirect, mfaScope)
		st = f.mfaStatus(tr.AccessToken)
		if v, has := st["passkeys"]; !has || v != float64(0) || st["enabled"] != false {
			t.Fatalf("status = %v", st)
		}
	})

	// I31: a removal of TOTP keeps the passkey and the passkey sessions. A removal of a
	// passkey ends the passkey sessions and keeps TOTP.
	t.Run("I31_removal_rules", func(t *testing.T) {
		u := f.newPasskeyUser("i31@example.com", swa.ES256, demoRole)
		// A session with a passkey, made after the registration.
		hwkWeb := f.a.NewWeb()
		if resp, _ := f.passkeyLogin(hwkWeb, u.key, ""); resp.StatusCode != http.StatusOK {
			t.Fatal("passkey login")
		}
		f.a.trackSession(hwkWeb)
		// TOTP on the web of the registration, then a TOTP session.
		f.setupTOTP(u.web)
		if resp, _ := u.web.PostForm(t, "/account/totp/remove", url.Values{}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("remove TOTP: %d", resp.StatusCode)
		}
		if f.passkeyRows(u.id) != 1 || f.countWhere(`SELECT count(*) FROM user_totp WHERE user_id = $1`, u.id) != 0 {
			t.Fatal("TOTP is removed and the passkey stays")
		}
		if got := methodsOf(t, f, hwkWeb); got != "hwk user mfa" {
			t.Fatalf("the passkey session after the removal of TOTP = %q", got)
		}
		if got := methodsOf(t, f, u.web); got != "pwd" {
			t.Fatalf("the TOTP session after the removal of TOTP = %q", got)
		}
		// Now TOTP again with a passkey. A removal of the passkey ends the passkey sessions.
		v := f.newPasskeyUser("i31b@example.com", swa.ES256, demoRole)
		f.setupTOTP(v.web)
		tr := f.passkeyCodeFlow(f.a.NewWeb(), v.key, "admin-ui", adminRedirect, mfaOfflineFlow, nil)
		hwkWeb2 := f.a.NewWeb()
		f.passkeyLogin(hwkWeb2, v.key, "")
		// The browser of the TOTP setup got the methods of TOTP, so it has a fresh MFA session.
		id := f.passkeyIDs(v.id)[0]
		resp, _ := v.web.PostForm(t, "/account/passkeys/"+id+"/remove", url.Values{})
		status(t, resp, http.StatusSeeOther, "remove the passkey on the page")
		if f.passkeyRows(v.id) != 0 || f.countWhere(`SELECT count(*) FROM user_totp WHERE user_id = $1`, v.id) != 1 {
			t.Fatal("the passkey is removed and TOTP stays")
		}
		if f.countWhere(`SELECT count(*) FROM sessions WHERE user_id = $1 AND 'hwk' = ANY(amr) AND revoked_at IS NULL`, v.id) != 0 {
			t.Fatal("the sessions with a passkey must end")
		}
		if f.countWhere(`SELECT count(*) FROM refresh_token_families WHERE user_id = $1 AND 'hwk' = ANY(amr) AND revoked_at IS NULL`, v.id) != 0 {
			t.Fatal("the refresh token families with a passkey must end")
		}
		if resp, r := f.refresh("admin-ui", tr.RefreshToken); resp.StatusCode == http.StatusOK || r.AccessToken != "" {
			t.Fatalf("refresh after the removal: %d", resp.StatusCode)
		}
		if resp, _ := hwkWeb2.Get(t, "/account/security"); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("a revoked session: %d", resp.StatusCode)
		}
	})

	// I33: the hosted removal form for the last passkey of a user with TOTP. The
	// page of the security settings shows the count and the link.
	t.Run("I33_hosted_removal", func(t *testing.T) {
		u := f.newPasskeyUser("i33@example.com", swa.ES256, demoRole)
		f.setupTOTP(u.web)
		resp, body := u.web.Get(t, "/account/security")
		status(t, resp, http.StatusOK, "GET /account/security")
		if !strings.Contains(string(body), "Passkeys: 1") || !strings.Contains(string(body), `href="/account/passkeys"`) {
			t.Fatalf("security page: %s", body)
		}
		resp, body = u.web.Get(t, "/account/passkeys")
		status(t, resp, http.StatusOK, "GET /account/passkeys")
		if !strings.Contains(string(body), "Register at least two passkeys") || strings.Contains(string(body), "credential") ||
			!strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
			t.Fatalf("passkey page: %s", body)
		}
		id := f.passkeyIDs(u.id)[0]
		notices := len(noticesOf(t, f.a, "mfa_passkey_removed"))
		resp, _ = u.web.PostForm(t, "/account/passkeys/"+id+"/remove", url.Values{})
		status(t, resp, http.StatusSeeOther, "remove")
		if resp.Header.Get("Location") != "/login" || f.passkeyRows(u.id) != 0 {
			t.Fatalf("Location %q rows %d", resp.Header.Get("Location"), f.passkeyRows(u.id))
		}
		if len(noticesOf(t, f.a, "mfa_passkey_removed")) != notices+1 {
			t.Fatal("no notice")
		}
	})

	// I20: the script.
	t.Run("I20_script", func(t *testing.T) {
		resp, body := f.a.Get(t, "/assets/passkey.js")
		status(t, resp, http.StatusOK, "GET /assets/passkey.js")
		if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") || resp.Header.Get("Cache-Control") != "public, max-age=3600" {
			t.Fatalf("headers = %v", resp.Header)
		}
		for _, bad := range []string{"eval(", "innerHTML", "document.write", "http://", "https://"} {
			if strings.Contains(string(body), bad) {
				t.Errorf("the script has %q", bad)
			}
		}
		// The login page has the button and the script, and the password form.
		resp, body = f.a.Get(t, "/login")
		status(t, resp, http.StatusOK, "GET /login")
		for _, want := range []string{"Log in with a passkey", `src="/assets/passkey.js"`, `name="password"`} {
			if !strings.Contains(string(body), want) {
				t.Errorf("the login page has no %q", want)
			}
		}
		if strings.Contains(string(body), "<script>") {
			t.Error("an inline script")
		}
	})

	// I17: the bucket passkey. The rate limit answers with JSON.
	t.Run("I17_rate_limit", func(t *testing.T) {
		// The tests share the client IP. A server with an own Valkey has its own counters.
		vk := containers.Valkey(t, containers.WithValkeyImage(testserver.ValkeyImage))
		hv := &harness{env: &testserver.Env{PG: h.env.PG, VK: vk}, ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
		g := newFixture(t, hv, mfaOptions(testserver.WithRateLimits(map[string]ratelimit.Rule{"passkey": {Limit: 2, Window: time.Minute}}))...)
		web := g.a.NewWeb()
		for i := 0; i < 2; i++ {
			resp, _ := web.PostJSON(t, "/login/passkey/options", []byte(`{}`))
			status(t, resp, http.StatusOK, "options inside the limit")
		}
		resp, b := web.PostJSON(t, "/login/passkey/options", []byte(`{}`))
		if resp.StatusCode != http.StatusTooManyRequests || strings.TrimSpace(string(b)) != `{"error":"rate_limited"}` || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("third request: %d %s", resp.StatusCode, b)
		}
		resp, b = web.PostJSON(t, "/login/mfa/passkey/options", []byte(`{}`))
		if resp.StatusCode != http.StatusTooManyRequests || strings.TrimSpace(string(b)) != `{"error":"rate_limited"}` {
			t.Fatalf("the other route: %d %s", resp.StatusCode, b)
		}
	})

	// I18: Valkey stops during a passkey login.
	t.Run("I18_valkey_down", func(t *testing.T) {
		vk := containers.Valkey(t, containers.WithValkeyImage(testserver.ValkeyImage))
		hv := &harness{env: &testserver.Env{PG: h.env.PG, VK: vk}, ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
		v := newFixture(t, hv, mfaOptions()...)
		u := v.newPasskeyUser("i18@example.com", swa.ES256, demoRole)
		web := v.a.NewWeb()
		_, _, raw := v.jsonPost(web, "/login/passkey/options", []byte(`{}`))
		response := u.key.Get(t, raw)
		sessions := v.countWhere(`SELECT count(*) FROM sessions`)
		if err := vk.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		resp, _ := web.PostJSON(t, "/login/passkey/finish", response)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("finish with Valkey down: %d", resp.StatusCode)
		}
		if v.countWhere(`SELECT count(*) FROM sessions`) != sessions {
			t.Fatal("no session may be made")
		}
	})

	// I19: an issuer with an IP address turns passkeys off.
	t.Run("I19_ip_issuer", func(t *testing.T) {
		g := newFixture(t, h, mfaOptions(testserver.WithConfigure(func(c *config.Config) {
			c.Issuer = strings.Replace(c.Issuer, "localhost", "127.0.0.1", 1)
		}))...)
		if n := len(recordsOf(t, g.a, "identity.passkeys.off: the issuer host is an IP address, so passkeys are off")); n != 1 {
			t.Fatalf("warn records = %d", n)
		}
		resp, body := g.a.Get(t, "/login")
		status(t, resp, http.StatusOK, "GET /login")
		if strings.Contains(string(body), "passkey") || strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src") {
			t.Fatalf("the login page must have no passkey: %s", body)
		}
		web := g.a.NewWeb()
		if resp, _ := web.PostJSON(t, "/login/passkey/options", []byte(`{}`)); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("options: %d", resp.StatusCode)
		}
		if resp, _ := g.a.Get(t, "/assets/passkey.js"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("script: %d", resp.StatusCode)
		}
		g.passwordLogin(web, "admin@example.com", adminPassword, "/login/done")
		if resp, _ := web.Get(t, "/account/passkeys"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET /account/passkeys: %d", resp.StatusCode)
		}
		if resp, _ := web.PostForm(t, "/account/passkeys/00000000-0000-4000-8000-0000000000ee/remove", url.Values{}); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("remove form: %d", resp.StatusCode)
		}
	})

	// I30: passkeys off with the setting. The API stays. A stored passkey does not
	// count as a second factor.
	t.Run("I30_off", func(t *testing.T) {
		off := testserver.WithConfigure(func(c *config.Config) { c.WebAuthn.Enabled = false })
		g := newFixture(t, h, mfaOptions(requireAdmins(), off)...)
		const insert = `INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, aaguid, backup_eligible, backup_state, name, created_at)
			VALUES (gen_random_uuid(), $1, $2, '\x01', 0, '\x00', true, true, 'Stored', now())`
		// An admin with only a stored passkey goes to the TOTP setup.
		admin := g.userID("admin@example.com")
		if _, err := g.a.Pool(t).Exec(ctx, insert, admin, []byte("admin-credential")); err != nil {
			t.Fatal(err)
		}
		web := g.a.NewWeb()
		g.passwordLogin(web, "admin@example.com", adminPassword, "/account/totp?required=1")
		// A user with TOTP and a stored passkey. The rule for admins is off here.
		g = newFixture(t, h, mfaOptions(off)...)
		u := g.newPasskeyUserOff("i30@example.com")
		if _, err := g.a.Pool(t).Exec(ctx, insert, u.id, []byte("user-credential")); err != nil {
			t.Fatal(err)
		}
		tr := g.mfaToken(u, "admin-ui", adminRedirect, mfaScope, nil)
		resp, m := g.api(tr.AccessToken, http.MethodGet, "/v1/me/passkeys", nil)
		if items, _ := m["items"].([]any); resp.StatusCode != http.StatusOK || len(items) != 1 {
			t.Fatalf("MePasskeys_list: %d %v", resp.StatusCode, m)
		}
		id := g.passkeyIDs(u.id)[0]
		resp, m = g.apiRaw(tr.AccessToken, http.MethodPatch, "/v1/me/passkeys/"+id, `{"name":"Kept"}`)
		if resp.StatusCode != http.StatusOK || m["name"] != "Kept" {
			t.Fatalf("MePasskeys_update: %d %v", resp.StatusCode, m)
		}
		// A user with a stored passkey and no TOTP: MFA is not enabled.
		plain := g.newUser(g.adminToken(adminScopes), "i30b@example.com", userPassword, demoRole)
		if _, err := g.a.Pool(t).Exec(ctx, insert, plain, []byte("plain-credential")); err != nil {
			t.Fatal(err)
		}
		ptr, _ := g.login("i30b@example.com", userPassword, "admin-ui", adminRedirect, mfaScope)
		st := g.mfaStatus(ptr.AccessToken)
		if st["enabled"] != false || st["passkeys"] != float64(1) {
			t.Fatalf("status = %v", st)
		}
	})

	// I21: no log record and no span holds a challenge, a credential ID, or a user handle.
	t.Run("I21_no_secrets_in_telemetry", func(t *testing.T) {
		h.ledger.mu.Lock()
		defer h.ledger.mu.Unlock()
		if len(h.ledger.flow) < 50 {
			t.Fatalf("the ledger has %d values", len(h.ledger.flow))
		}
		var texts []string
		for _, l := range h.ledger.logs {
			texts = append(texts, l.Text())
		}
		spans := spansText()
		for _, v := range h.ledger.flow {
			for _, text := range texts {
				if strings.Contains(text, v) {
					t.Fatalf("a log record holds a secret value (%s...)", v[:4])
				}
			}
			if strings.Contains(spans, v) {
				t.Fatalf("a span holds a secret value (%s...)", v[:4])
			}
		}
	})
}

// newPasskeyUserOff makes a user with TOTP, for a server with passkeys off.
func (f *fixture) newPasskeyUserOff(email string) *mfaUser {
	f.t.Helper()
	return f.newTOTPUser(email, "demo:agent")
}

// The tests of the rule "MFA for admins" with passkeys.
func TestIssue15AdminIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	g := newFixture(t, h, mfaOptions(requireAdmins())...)
	admin := g.newMFAAdmin()
	const demoRole = "demo:agent"
	adminTok := func() string { return g.adminMFAToken(admin, adminMFAScopes) }

	// I32, I14: a required admin with no factor registers a passkey on the page of the
	// passkeys, and the code flow goes on. Later the password and the passkey give a code.
	t.Run("I32_I14_required_admin", func(t *testing.T) {
		g.newUser(adminTok(), "i32@example.com", userPassword, "identity:admin")
		web := g.a.NewWeb()
		g.passwordLogin(web, "i32@example.com", userPassword, "/account/totp?required=1")
		p := testserver.NewPKCE(t)
		resp := web.Authorize(t, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, p, nil))
		loc := testserver.Location(t, resp)
		ar := loc.Query().Get("authRequest")
		if loc.Path != "/account/totp" || ar == "" {
			t.Fatalf("authorize: %s", loc)
		}
		g.a.ledger.add(&g.a.ledger.flow, ar)
		resp, body := web.Get(t, loc.RequestURI())
		status(t, resp, http.StatusOK, "GET the setup page")
		if !strings.Contains(string(body), `href="/account/passkeys?required=1&amp;authRequest=`+ar) || strings.Contains(string(body), "<script") {
			t.Fatalf("the TOTP page needs the link to the passkeys and no script: %s", body)
		}
		resp, body = web.Get(t, "/account/passkeys?required=1&authRequest="+ar)
		status(t, resp, http.StatusOK, "GET the passkey page")
		if !strings.Contains(string(body), `data-auth-request="`+ar+`"`) || !strings.Contains(string(body), "Add a passkey to continue") {
			t.Fatalf("passkey page: %s", body)
		}
		key := g.newAuthenticator(swa.ES256)
		req, _ := json.Marshal(map[string]string{"name": "Admin key", "authRequest": ar})
		resp, _, raw := g.jsonPost(web, "/account/passkeys/options", req)
		status(t, resp, http.StatusOK, "options")
		resp, m, _ := g.jsonPost(web, "/account/passkeys/finish", key.Create(t, raw))
		status(t, resp, http.StatusOK, "finish")
		if m["redirect"] != "/oauth/authorize/continue?authRequest="+url.QueryEscape(ar) {
			t.Fatalf("finish = %v", m)
		}
		if got := methodsOf(t, g, web); got != "pwd hwk user mfa" {
			t.Fatalf("session methods = %q", got)
		}
		g.a.trackSession(web)
		resp, _ = web.Get(t, m["redirect"].(string))
		status(t, resp, http.StatusFound, "continue")
		tr := g.exchangeCode(testserver.Location(t, resp), p, "admin-ui", adminRedirect)
		if got := amrOf(t, tr.AccessToken); got != "pwd hwk user mfa" {
			t.Fatalf("amr = %q", got)
		}

		// I14: a new browser. The password, then the passkey. The code is issued after the second factor.
		web2 := g.a.NewWeb()
		p2 := testserver.NewPKCE(t)
		g.startMFALogin(web2, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, p2, nil), "i32@example.com", userPassword)
		_, _, raw = g.jsonPost(web2, "/login/mfa/passkey/options", []byte(`{}`))
		resp, m, _ = g.jsonPost(web2, "/login/mfa/passkey/finish", key.Get(t, raw))
		status(t, resp, http.StatusOK, "second factor")
		g.a.trackSession(web2)
		resp, _ = web2.Get(t, m["redirect"].(string))
		status(t, resp, http.StatusFound, "continue")
		tr = g.exchangeCode(testserver.Location(t, resp), p2, "admin-ui", adminRedirect)
		if got := amrOf(t, tr.AccessToken); got != "pwd hwk user mfa" {
			t.Fatalf("amr = %q", got)
		}
	})

	// I16: the reset of a user with TOTP, recovery codes, and two passkeys.
	t.Run("I16_reset", func(t *testing.T) {
		u := g.newPasskeyUserWith(adminTok(), "i16@example.com", swa.ES256, demoRole)
		if resp, m := g.registerPasskey(u.web, u.key, "Second"); resp.StatusCode != http.StatusOK {
			t.Fatalf("second passkey: %v", m)
		}
		g.setupTOTP(u.web)
		if g.passkeyRows(u.id) != 2 {
			t.Fatalf("passkeys = %d", g.passkeyRows(u.id))
		}
		tok := adminTok()
		resp, _ := g.api(tok, http.MethodDelete, "/v1/users/"+u.id+"/mfa", nil)
		status(t, resp, http.StatusNoContent, "UserMfa_reset")
		if g.passkeyRows(u.id) != 0 || g.countWhere(`SELECT count(*) FROM user_totp WHERE user_id = $1`, u.id) != 0 ||
			g.countWhere(`SELECT count(*) FROM recovery_codes WHERE user_id = $1`, u.id) != 0 ||
			g.countWhere(`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, u.id) != 0 {
			t.Fatal("the reset must remove all factors and end all sessions")
		}
		st, m := g.api(tok, http.MethodGet, "/v1/users/"+u.id+"/mfa", nil)
		if st.StatusCode != http.StatusOK || m["enabled"] != false || m["passkeys"] != float64(0) {
			t.Fatalf("status = %d %v", st.StatusCode, m)
		}
	})

	// I14 (rule of the last factor): an admin with a passkey and TOTP can remove TOTP. An admin with
	// one passkey only cannot remove the passkey.
	t.Run("I14_last_factor_of_admin", func(t *testing.T) {
		u := g.newPasskeyUserWith(adminTok(), "i14@example.com", swa.ES256)
		if resp, m := g.api(adminTok(), http.MethodPut, "/v1/users/"+u.id+"/roles/identity:admin", nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("assign: %d %v", resp.StatusCode, m)
		}
		id := g.passkeyIDs(u.id)[0]
		resp, body := u.web.PostForm(t, "/account/passkeys/"+id+"/remove", url.Values{})
		if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "MFA is required") || g.passkeyRows(u.id) != 1 {
			t.Fatalf("remove the last factor: %d %s", resp.StatusCode, body)
		}
		tok := g.passkeyToken(u, passkeyScope)
		resp2, m := g.apiRaw(tok, http.MethodDelete, "/v1/me/passkeys/"+id, "")
		if resp2.StatusCode != http.StatusConflict || m["code"] != "mfa_required" {
			t.Fatalf("remove with the API: %d %v", resp2.StatusCode, m)
		}
	})
}
