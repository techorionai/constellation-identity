//go:build integration

package services_test

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

// sessionRow reads the columns of the session of a browser.
type sessionRow struct {
	ID        string
	CreatedAt time.Time
	AuthTime  time.Time
	ExpiresAt time.Time
}

func (f *fixture) sessionRow(web *testserver.Web) sessionRow {
	f.t.Helper()
	var r sessionRow
	row := f.a.Pool(f.t).QueryRow(ctx,
		`SELECT id, created_at, auth_time, expires_at FROM sessions WHERE token_hash = encode(sha256($1::bytea), 'hex')`,
		web.Cookie(pages.CookieName))
	if err := row.Scan(&r.ID, &r.CreatedAt, &r.AuthTime, &r.ExpiresAt); err != nil {
		f.t.Fatalf("session row: %v", err)
	}
	return r
}

func TestIssue4SessionsIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h)
	admin := f.adminToken(adminScopes)
	f.newUser(admin, "agent@example.com", userPass2, "demo:agent")
	f.newUser(admin, "other@example.com", userPass2, "demo:agent")

	// U13a, U13: userinfo.
	t.Run("userinfo", func(t *testing.T) {
		tr, _ := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, "openid email demo:ticket:read")
		resp, b := f.a.Do(t, http.MethodGet, "/oauth/userinfo", tr.AccessToken, "")
		m := decode(t, b)
		if resp.StatusCode != http.StatusOK || m["email"] != "agent@example.com" || m["sub"] == "" || m["email_verified"] != true {
			t.Fatalf("userinfo: %d %s", resp.StatusCode, b)
		}
		resp, _ = f.a.Do(t, http.MethodGet, "/oauth/userinfo", tr.IDToken, "")
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "invalid_token") {
			t.Fatalf("ID token as bearer: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
		if resp, _ = f.a.Do(t, http.MethodGet, "/oauth/userinfo", "", ""); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("no token: %d", resp.StatusCode)
		}
		svc := f.serviceToken()
		resp, _ = f.a.Do(t, http.MethodGet, "/oauth/userinfo", svc, "")
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "insufficient_scope") {
			t.Fatalf("service token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
	})

	// I18, I18b, I18f: a same-user re-login keeps the session.
	t.Run("I18_relogin_keeps_session", func(t *testing.T) {
		web := f.a.NewWeb()
		first := f.loginWith(web, "agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		before := f.sessionRow(web)
		oldCookie := web.Cookie(pages.CookieName)
		_, c1 := testserver.JWTClaims(t, first.IDToken)
		f.advance(10 * time.Second)

		p := testserver.NewPKCE(t)
		loc := web.CodeFlow(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, map[string]string{"prompt": "login"}), "agent@example.com", userPass2)
		_, second := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", codeOf(t, loc), demoRedirect, p.Verifier))
		after := f.sessionRow(web)
		_, c2 := testserver.JWTClaims(t, second.IDToken)
		if c1["sid"] != c2["sid"] || after.ID != before.ID {
			t.Fatalf("the sid must not change: %v %v", c1["sid"], c2["sid"])
		}
		if !after.CreatedAt.Equal(before.CreatedAt) || !after.ExpiresAt.Equal(before.ExpiresAt) || !after.AuthTime.After(before.AuthTime) {
			t.Fatalf("created_at, expires_at, and auth_time: %+v %+v", before, after)
		}
		if c2["auth_time"].(float64) <= c1["auth_time"].(float64) || int64(c2["auth_time"].(float64)) != after.AuthTime.Unix() {
			t.Fatalf("auth_time of the ID tokens: %v %v, row %v", c1["auth_time"], c2["auth_time"], after.AuthTime)
		}
		if f.countWhere(`SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = 'agent@example.com' AND s.id = $1`, after.ID) != 1 {
			t.Fatal("one session row")
		}
		// I18b: the cookie value changed, and the old value stops.
		if web.Cookie(pages.CookieName) == oldCookie {
			t.Fatal("the cookie value must change")
		}
		w2 := f.a.NewWeb()
		w2.SetCookie(pages.CookieName, oldCookie)
		if resp, _ := w2.Get(t, "/login/done"); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("old cookie: %d", resp.StatusCode)
		}
		if resp, _ := web.Get(t, "/login/done"); resp.StatusCode != http.StatusOK {
			t.Fatalf("new cookie: %d", resp.StatusCode)
		}
		// I18f: the refresh token of the first flow works, and the expiry is the same.
		resp, r := f.refresh("demo-ui", first.RefreshToken)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("refresh after the re-login: %+v", r)
		}
		var exp time.Time
		if err := f.a.Pool(t).QueryRow(ctx, `SELECT max(expires_at) FROM refresh_tokens WHERE family_id IN (SELECT id FROM refresh_token_families WHERE session_id = $1)`, after.ID).Scan(&exp); err != nil {
			t.Fatal(err)
		}
		if !exp.Equal(after.ExpiresAt) {
			t.Fatalf("refresh expiry = %v, session expiry = %v", exp, after.ExpiresAt)
		}
	})

	// I18a: another user logs in with the cookie of the first user.
	t.Run("I18a_other_user", func(t *testing.T) {
		webA := f.a.NewWeb()
		trA := f.loginWith(webA, "agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		sidA := f.sessionRow(webA)
		webB := f.a.NewWeb()
		webB.SetCookie(pages.CookieName, webA.Cookie(pages.CookieName))
		resp, _ := webB.PostForm(t, "/login", url.Values{"email": {"other@example.com"}, "password": {userPass2}})
		status(t, resp, http.StatusSeeOther, "login of B")
		if f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NOT NULL`, sidA.ID) != 1 {
			t.Fatal("the session of A must be revoked")
		}
		if _, r := f.refresh("demo-ui", trA.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("refresh of A: %+v", r)
		}
		b := f.sessionRow(webB)
		if b.ID == sidA.ID || !b.AuthTime.Equal(b.CreatedAt) {
			t.Fatalf("B must have a new session: %+v", b)
		}
	})

	// I18c: a revoked, an idle expired, and no session. A new session starts.
	t.Run("I18c_previous_session_not_valid", func(t *testing.T) {
		for name, prepare := range map[string]func(web *testserver.Web, sid string){
			"revoked": func(_ *testserver.Web, sid string) {
				if _, err := f.a.Pool(t).Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1`, sid); err != nil {
					t.Fatal(err)
				}
			},
			"idle expired": func(_ *testserver.Web, sid string) { f.advance(13 * time.Hour) },
			"no session":   func(web *testserver.Web, _ string) { web.SetCookie(pages.CookieName, "unknown-cookie") },
		} {
			web := f.a.NewWeb()
			tr := f.loginWith(web, "agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
			old := f.sessionRow(web)
			prepare(web, old.ID)
			resp, _ := web.PostForm(t, "/login", url.Values{"email": {"agent@example.com"}, "password": {userPass2}})
			status(t, resp, http.StatusSeeOther, name)
			if name != "no session" && f.sessionRow(web).ID == old.ID {
				t.Fatalf("%s: a new session must start", name)
			}
			// With no previous session, the real session of the first login is not the
			// previous session of this login, so it stays.
			if _, r := f.refresh("demo-ui", tr.RefreshToken); (name == "no session") == (r.Error == "invalid_grant") {
				t.Fatalf("%s: refresh: %+v", name, r)
			}
		}
	})

	// I18d: a parallel logout and a re-login with the same cookie.
	t.Run("I18d_parallel_logout_relogin", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			web := f.a.NewWeb()
			f.loginWith(web, "agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
			oldCookie := web.Cookie(pages.CookieName)
			w1, w2 := f.a.NewWeb(), f.a.NewWeb()
			w1.SetCookie(pages.CookieName, oldCookie)
			w2.SetCookie(pages.CookieName, oldCookie)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); w1.PostForm(t, "/logout", url.Values{}) }()
			go func() {
				defer wg.Done()
				w2.PostForm(t, "/login", url.Values{"email": {"agent@example.com"}, "password": {userPass2}})
			}()
			wg.Wait()
			// The old value never works.
			probe := f.a.NewWeb()
			probe.SetCookie(pages.CookieName, oldCookie)
			if resp, _ := probe.Get(t, "/login/done"); resp.StatusCode == http.StatusOK {
				t.Fatal("the old cookie value must not work")
			}
		}
	})

	// I18e: a wrong password changes nothing.
	t.Run("I18e_wrong_password", func(t *testing.T) {
		web := f.a.NewWeb()
		tr := f.loginWith(web, "agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		before, cookie := f.sessionRow(web), web.Cookie(pages.CookieName)
		f.advance(time.Second)
		resp, _ := web.PostForm(t, "/login", url.Values{"email": {"agent@example.com"}, "password": {"wrong password 9999"}})
		status(t, resp, http.StatusUnauthorized, "wrong password")
		if after := f.sessionRow(web); after != before || web.Cookie(pages.CookieName) != cookie {
			t.Fatalf("the session changed: %+v %+v", before, after)
		}
		if resp, _ := f.refresh("demo-ui", tr.RefreshToken); resp.StatusCode != http.StatusOK {
			t.Fatal("the refresh token must work")
		}
	})

	// I8 to I8e: end session.
	t.Run("I8_end_session", func(t *testing.T) {
		// I8: a valid hint with the sid of the cookie session.
		web := f.a.NewWeb()
		tr := f.loginWith(web, "agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		sid := f.sessionRow(web).ID
		q := url.Values{"id_token_hint": {tr.IDToken}, "post_logout_redirect_uri": {demoPostLogout}, "state": {"bye"}}
		resp, _ := web.Get(t, "/oauth/end_session?"+q.Encode())
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != demoPostLogout+"?state=bye" {
			t.Fatalf("end session: %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		if f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NOT NULL`, sid) != 1 {
			t.Fatal("the session must be revoked")
		}
		if rev, total := f.familyRevoked(sid); rev != total || total != 1 {
			t.Fatalf("families: %d of %d", rev, total)
		}
		// I8e: a valid hint and no session cookie.
		w0 := f.a.NewWeb()
		resp, _ = w0.Get(t, "/oauth/end_session?"+q.Encode())
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != demoPostLogout+"?state=bye" {
			t.Fatalf("no cookie: %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		q.Del("post_logout_redirect_uri")
		if resp, body := w0.Get(t, "/oauth/end_session?"+q.Encode()); resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "You are logged out") {
			t.Fatalf("no cookie, no URI: %d", resp.StatusCode)
		}

		// I8a: an unregistered post-logout URI is not used.
		web = f.a.NewWeb()
		tr = f.loginWith(web, "agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		resp, body := web.Get(t, "/oauth/end_session?"+url.Values{"id_token_hint": {tr.IDToken}, "post_logout_redirect_uri": {"https://evil.example.com/"}}.Encode())
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "You are logged out") {
			t.Fatalf("unregistered URI: %d", resp.StatusCode)
		}
		// I8b: a post-logout URI of another client is not used.
		web = f.a.NewWeb()
		tr = f.loginWith(web, "agent@example.com", userPass2, "loopback-ui", loopbackRedirect, demoScope)
		resp, _ = web.Get(t, "/oauth/end_session?"+url.Values{"id_token_hint": {tr.IDToken}, "post_logout_redirect_uri": {demoPostLogout}}.Encode())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("URI of another client: %d", resp.StatusCode)
		}

		// I8c: a hint with another sid does not end the session of the cookie.
		webA := f.a.NewWeb()
		f.loginWith(webA, "agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		sidA := f.sessionRow(webA).ID
		webB := f.a.NewWeb()
		trB := f.loginWith(webB, "other@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		sidB := f.sessionRow(webB).ID
		resp, body = webA.Get(t, "/oauth/end_session?"+url.Values{"id_token_hint": {trB.IDToken}, "post_logout_redirect_uri": {demoPostLogout}}.Encode())
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" || !strings.Contains(string(body), "<form") {
			t.Fatalf("confirm: %d", resp.StatusCode)
		}
		if f.countWhere(`SELECT count(*) FROM sessions WHERE id IN ($1, $2) AND revoked_at IS NULL`, sidA, sidB) != 2 {
			t.Fatal("no session may change before the POST")
		}
		resp, body = webA.PostForm(t, "/oauth/end_session", url.Values{})
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "You are logged out") || resp.Header.Get("Location") != "" {
			t.Fatalf("confirm POST: %d", resp.StatusCode)
		}
		if f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NOT NULL`, sidA) != 1 ||
			f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NULL`, sidB) != 1 {
			t.Fatal("only the session of the cookie may end")
		}
		// A POST with no session changes nothing.
		resp, _ = f.a.NewWeb().PostForm(t, "/oauth/end_session", url.Values{})
		status(t, resp, http.StatusOK, "POST with no session")

		// I8d: no hint gives the confirmation form.
		webC := f.a.NewWeb()
		f.loginWith(webC, "agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		sidC := f.sessionRow(webC).ID
		resp, body = webC.Get(t, "/oauth/end_session")
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "<form") || f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NULL`, sidC) != 1 {
			t.Fatalf("no hint: %d", resp.StatusCode)
		}
		// A bad hint gives an error page.
		resp, _ = webC.Get(t, "/oauth/end_session?id_token_hint=garbage")
		status(t, resp, http.StatusBadRequest, "bad hint")
		// An access token is not a valid hint.
		tr2, _ := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		resp, _ = webC.Get(t, "/oauth/end_session?"+url.Values{"id_token_hint": {tr2.AccessToken}}.Encode())
		status(t, resp, http.StatusBadRequest, "access token as hint")
	})

	// I15: CORS.
	t.Run("I15_cors", func(t *testing.T) {
		do := func(method, path, origin string) http.Header {
			req, _ := http.NewRequestWithContext(ctx, method, f.a.PublicURL+path, strings.NewReader(""))
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			if method == http.MethodOptions {
				req.Header.Set("Access-Control-Request-Method", "POST")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			return resp.Header
		}
		for _, path := range []string{"/oauth/token", "/oauth/revoke", "/oauth/userinfo"} {
			resp := do(http.MethodOptions, path, "https://demo.example.com")
			if resp.Get("Access-Control-Allow-Origin") != "https://demo.example.com" || resp.Get("Access-Control-Allow-Methods") != "GET, POST" ||
				resp.Get("Access-Control-Allow-Headers") != "Authorization, Content-Type" || resp.Get("Access-Control-Max-Age") != "600" ||
				resp.Get("Access-Control-Allow-Credentials") != "" || !strings.Contains(resp.Get("Vary"), "Origin") {
				t.Fatalf("%s preflight: %v", path, resp)
			}
			resp = do(http.MethodOptions, path, "https://evil.example.com")
			if resp.Get("Access-Control-Allow-Origin") != "" || !strings.Contains(resp.Get("Vary"), "Origin") {
				t.Fatalf("%s preflight of another origin: %v", path, resp)
			}
		}
		// I15a: real requests.
		resp := do(http.MethodGet, "/oauth/userinfo", "https://demo.example.com")
		if resp.Get("Access-Control-Allow-Origin") != "https://demo.example.com" || resp.Get("Vary") == "" {
			t.Fatalf("userinfo from a registered origin: %v", resp)
		}
		resp = do(http.MethodGet, "/oauth/userinfo", "https://evil.example.com")
		if resp.Get("Access-Control-Allow-Origin") != "" || resp.Get("Vary") == "" {
			t.Fatalf("userinfo from another origin: %v", resp)
		}
		// I15c: the loopback rule.
		if resp = do(http.MethodOptions, "/oauth/token", "http://127.0.0.1:5555"); resp.Get("Access-Control-Allow-Origin") != "http://127.0.0.1:5555" {
			t.Fatalf("loopback IP with any port: %v", resp)
		}
		if resp = do(http.MethodOptions, "/oauth/token", "http://localhost:5555"); resp.Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("localhost needs the exact port: %v", resp)
		}
		if resp = do(http.MethodOptions, "/oauth/token", "http://localhost:3000"); resp.Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
			t.Fatalf("localhost with the exact port: %v", resp)
		}
		// I15b, I15d: a client that the API adds and disables.
		r, m := f.api(admin, http.MethodPost, "/v1/clients", map[string]any{"type": "public", "app": "demo", "name": "Cors", "redirectUris": []string{"https://cors.example.com/cb"}})
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("create: %d %v", r.StatusCode, m)
		}
		if resp = do(http.MethodOptions, "/oauth/token", "https://cors.example.com"); resp.Get("Access-Control-Allow-Origin") == "" {
			t.Fatal("a new client must be allowed")
		}
		f.api(admin, http.MethodPatch, "/v1/clients/"+m["id"].(string), map[string]any{"disabled": true})
		if resp = do(http.MethodOptions, "/oauth/token", "https://cors.example.com"); resp.Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("a disabled client must not be allowed")
		}
	})
}

// serviceToken gives an access token of a service client.
func (f *fixture) serviceToken() string {
	f.t.Helper()
	c := f.serviceClient
	return token(f.t, f.a.Server, c, "identity", "identity:manifest:publish")
}
