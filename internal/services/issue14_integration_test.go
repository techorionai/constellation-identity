//go:build integration

package services_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	platformconfig "github.com/techorionai/constellation-platform-go/config"
	"github.com/techorionai/constellation-platform-go/resources/test/containers"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/internal/services"
	"github.com/techorionai/constellation-identity/migrations"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

const (
	mfaScope       = "openid identity:mfa:manage_own"
	mfaOfflineFlow = "openid offline_access identity:mfa:manage_own"
	adminMFAScopes = "openid identity:mfa:reset identity:mfa:read identity:admin identity:user:read identity:user:write identity:role:read identity:role:assign identity:api_token:manage_own"
)

// mfaOptions are the options of a fixture of the MFA tests.
func mfaOptions(opts ...testserver.Option) []testserver.Option {
	return append([]testserver.Option{testserver.WithClockedVerifier()}, opts...)
}

// requireAdmins turns on the rule "MFA for admins" in a test server.
func requireAdmins() testserver.Option {
	return testserver.WithConfigure(func(c *config.Config) { c.MFA.RequireForAdmins = true })
}

// mfaUser is a user with TOTP and a browser that has a session.
type mfaUser struct {
	id       string
	email    string
	web      *testserver.Web
	secret   string
	codes    []string
	password string
}

// passwordLogin logs a user in with the password only, and asserts the redirect.
func (f *fixture) passwordLogin(web *testserver.Web, email, password, wantLocation string) {
	f.t.Helper()
	f.a.ledger.add(&f.a.ledger.passwords, password)
	resp, _ := web.PostForm(f.t, "/login", url.Values{"email": {email}, "password": {password}})
	status(f.t, resp, http.StatusSeeOther, "password login")
	if got := resp.Header.Get("Location"); got != wantLocation {
		f.t.Fatalf("password login: Location = %q, want %q", got, wantLocation)
	}
	f.a.trackSession(web)
}

// setupTOTP does the TOTP setup on the pages, with a browser that has a fresh
// session. It checks the headers of the pages. It moves the clock to the next
// time step, so that the next login can use a new code.
func (f *fixture) setupTOTP(web *testserver.Web) (secret string, codes []string) {
	f.t.Helper()
	resp, body := web.Get(f.t, "/account/totp")
	status(f.t, resp, http.StatusOK, "GET /account/totp")
	if resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "img-src 'self' data:") ||
		!strings.Contains(string(body), "data:image/png;base64,") || !strings.Contains(string(body), "<form") {
		f.t.Fatalf("setup page: headers %v", resp.Header)
	}
	if strings.Contains(string(body), "<script") {
		f.t.Fatal("the setup page must have no script")
	}
	secret = testserver.SetupSecretOf(f.t, body)
	resp, body = web.PostForm(f.t, "/account/totp", url.Values{"code": {testserver.TOTPCode(f.t, secret, f.clock.Now())}})
	status(f.t, resp, http.StatusOK, "POST /account/totp")
	if resp.Header.Get("Cache-Control") != "no-store" {
		f.t.Fatal("the recovery codes page needs no-store")
	}
	codes = testserver.RecoveryCodesOf(f.t, body)
	if len(codes) != 10 {
		f.t.Fatalf("recovery codes = %d", len(codes))
	}
	f.a.ledger.add(&f.a.ledger.flow, secret)
	for _, c := range codes {
		f.a.ledger.add(&f.a.ledger.flow, c)
		f.a.ledger.add(&f.a.ledger.flow, strings.ReplaceAll(c, "-", ""))
	}
	f.advance(31 * time.Second)
	return secret, codes
}

// newTOTPUser makes a user (the admin API makes it), logs it in, and sets up TOTP.
func (f *fixture) newTOTPUser(email string, roles ...string) *mfaUser {
	f.t.Helper()
	id := f.newUser(f.adminToken(adminScopes), email, userPassword, roles...)
	web := f.a.NewWeb()
	f.passwordLogin(web, email, userPassword, "/login/done")
	secret, codes := f.setupTOTP(web)
	return &mfaUser{id: id, email: email, web: web, secret: secret, codes: codes, password: userPassword}
}

// startMFALogin starts a code flow: the authorization request, the password,
// and the redirect to the second factor page. It returns the auth request ID.
func (f *fixture) startMFALogin(web *testserver.Web, q url.Values, email, password string) string {
	f.t.Helper()
	resp := web.Authorize(f.t, q)
	loc := testserver.Location(f.t, resp)
	if !strings.HasPrefix(loc.Path, "/login") {
		f.t.Fatalf("authorize: Location = %s, want a login page", loc)
	}
	id := loc.Query().Get("authRequest")
	f.a.ledger.add(&f.a.ledger.passwords, password)
	resp, _ = web.PostForm(f.t, "/login", url.Values{"email": {email}, "password": {password}, "authRequest": {id}})
	status(f.t, resp, http.StatusSeeOther, "POST /login")
	if got := resp.Header.Get("Location"); got != "/login/mfa" {
		f.t.Fatalf("POST /login: Location = %q, want /login/mfa", got)
	}
	if web.Cookie(pages.MFACookieName) == "" || web.Cookie(pages.CookieName) != "" && f.sessionRevoked(web) {
		f.t.Fatal("the pending login needs the cookie of the pending login")
	}
	f.a.ledger.add(&f.a.ledger.flow, web.Cookie(pages.MFACookieName))
	f.a.ledger.add(&f.a.ledger.flow, id)
	return id
}

func (f *fixture) sessionRevoked(web *testserver.Web) bool {
	f.t.Helper()
	return f.countWhere(`SELECT count(*) FROM sessions WHERE token_hash = encode(sha256($1::bytea), 'hex') AND revoked_at IS NOT NULL`, web.Cookie(pages.CookieName)) > 0
}

// finishMFALogin posts the second factor and follows the redirect of the code
// flow. It returns the redirect URL with the code.
func (f *fixture) finishMFALogin(web *testserver.Web, code string, recovery bool) *url.URL {
	f.t.Helper()
	form := url.Values{"code": {code}}
	if recovery {
		form.Set("recovery", "1")
	}
	if recovery {
		// A TOTP code has 6 digits, so it can match a number in a log record by chance.
		f.a.ledger.add(&f.a.ledger.flow, code)
	}
	resp, _ := web.PostForm(f.t, "/login/mfa", form)
	status(f.t, resp, http.StatusSeeOther, "POST /login/mfa")
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/oauth/authorize/continue?authRequest=") {
		f.t.Fatalf("POST /login/mfa: Location = %q", loc)
	}
	f.a.trackSession(web)
	resp, _ = web.Get(f.t, loc)
	status(f.t, resp, http.StatusFound, "continue")
	return testserver.Location(f.t, resp)
}

// exchangeCode trades a code for the tokens.
func (f *fixture) exchangeCode(loc *url.URL, p testserver.PKCE, clientID, redirect string) testserver.TokenResponse {
	f.t.Helper()
	code := loc.Query().Get("code")
	if code == "" {
		f.t.Fatalf("no code in %s", loc)
	}
	resp, tr := f.a.TokenRequest(f.t, testserver.CodeForm(clientID, code, redirect, p.Verifier))
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("token: status = %d, error = %s", resp.StatusCode, tr.Error)
	}
	for _, v := range []string{code, p.Verifier, tr.RefreshToken, tr.IDToken, tr.AccessToken} {
		if v != "" {
			f.a.ledger.add(&f.a.ledger.flow, v)
		}
	}
	return tr
}

// mfaToken does the full code flow with the password and the TOTP code. The
// clock moves to the next time step first.
func (f *fixture) mfaToken(u *mfaUser, clientID, redirect, scope string, extra map[string]string) testserver.TokenResponse {
	f.t.Helper()
	f.advance(31 * time.Second)
	p := testserver.NewPKCE(f.t)
	q := map[string]string{"prompt": "login"}
	for k, v := range extra {
		q[k] = v
	}
	f.startMFALogin(u.web, testserver.AuthorizeQuery(clientID, redirect, scope, p, q), u.email, u.password)
	loc := f.finishMFALogin(u.web, testserver.TOTPCode(f.t, u.secret, f.clock.Now()), false)
	return f.exchangeCode(loc, p, clientID, redirect)
}

// sessionToken does the code flow with the existing session of the browser.
func (f *fixture) sessionToken(u *mfaUser, clientID, redirect, scope string) testserver.TokenResponse {
	f.t.Helper()
	p := testserver.NewPKCE(f.t)
	loc := u.web.CodeFlow(f.t, testserver.AuthorizeQuery(clientID, redirect, scope, p, nil), u.email, u.password)
	return f.exchangeCode(loc, p, clientID, redirect)
}

func amrOf(t *testing.T, token string) string {
	t.Helper()
	_, claims := testserver.JWTClaims(t, token)
	raw, ok := claims["amr"].([]any)
	if !ok {
		return ""
	}
	parts := make([]string, len(raw))
	for i, v := range raw {
		parts[i], _ = v.(string)
	}
	return strings.Join(parts, " ")
}

func authTimeOf(t *testing.T, token string) float64 {
	t.Helper()
	_, claims := testserver.JWTClaims(t, token)
	v, _ := claims["auth_time"].(float64)
	return v
}

// adminMFAToken gives the access token of the admin of an MFA fixture. The
// admin has TOTP.
func (f *fixture) adminMFAToken(admin *mfaUser, scope string) string {
	f.t.Helper()
	return f.mfaToken(admin, "admin-ui", adminRedirect, scope, nil).AccessToken
}

// newMFAAdmin sets up TOTP for the first admin of a fixture with the rule on.
func (f *fixture) newMFAAdmin() *mfaUser {
	f.t.Helper()
	secret, codes := f.setupTOTP(f.admin)
	return &mfaUser{id: f.userID("admin@example.com"), email: "admin@example.com", web: f.admin, secret: secret, codes: codes, password: adminPassword}
}

func (f *fixture) userID(email string) string {
	f.t.Helper()
	var id string
	if err := f.a.Pool(f.t).QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&id); err != nil {
		f.t.Fatalf("user %s: %v", email, err)
	}
	return id
}

// mfaStatus calls GET /v1/me/mfa.
func (f *fixture) mfaStatus(tok string) map[string]any {
	f.t.Helper()
	resp, m := f.api(tok, http.MethodGet, "/v1/me/mfa", nil)
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("GET /v1/me/mfa: %d %v", resp.StatusCode, m)
	}
	return m
}

// I1: migration 0012 up and down, and the previous version runs on the new schema.
func TestIssue14MigrationIntegration(t *testing.T) {
	env := testserver.NewEnv(t)
	u, _ := env.PG.NewDatabase(t)
	pool, err := pgxpool.New(ctx, string(u))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrations(t, pool, 1, 11)
	const userID = "00000000-0000-4000-8000-0000000000aa"
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, name, status, created_at, updated_at) VALUES ($1, 'm@example.com', 'M', 'active', now(), now())`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at)
		VALUES ('00000000-0000-4000-8000-0000000000b1', $1, 'old-1', now(), now(), now() + interval '1 hour', now() + interval '1 day')`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clients (id, type, app, name, disabled, source, created_at, updated_at, redirect_uris, post_logout_redirect_uris)
		VALUES ('ui', 'public', 'demo', 'UI', false, 'config', now(), now(), '{}', '{}')`); err != nil {
		// The columns of the clients table can differ. A minimal insert follows.
		if _, err := pool.Exec(ctx, `INSERT INTO clients (id, type, app, name, disabled, source, created_at, updated_at) VALUES ('ui', 'service', 'demo', 'UI', false, 'config', now(), now())`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO refresh_token_families (id, session_id, client_id, user_id, scope, oidc_scopes, created_at)
		VALUES ('00000000-0000-4000-8000-0000000000c1', '00000000-0000-4000-8000-0000000000b1', 'ui', $1, 'demo:a:b', 'openid', now())`, userID); err != nil {
		t.Fatal(err)
	}
	applyMigrations(t, pool, 12, 12)
	var amr []string
	if err := pool.QueryRow(ctx, `SELECT amr FROM sessions WHERE id = '00000000-0000-4000-8000-0000000000b1'`).Scan(&amr); err != nil || len(amr) != 0 {
		t.Fatalf("amr of the old session = %v, %v", amr, err)
	}
	var authTimeNull bool
	if err := pool.QueryRow(ctx, `SELECT auth_time IS NULL FROM refresh_token_families WHERE id = '00000000-0000-4000-8000-0000000000c1'`).Scan(&authTimeNull); err != nil || !authTimeNull {
		t.Fatalf("auth_time of the old family is not NULL: %v %v", authTimeNull, err)
	}
	// The SQL of the previous version works on the new schema.
	for _, q := range []string{
		`SELECT id, user_id, token_hash, created_at, auth_time, last_seen_at, idle_expires_at, expires_at, revoked_at, user_agent, ip_address FROM sessions WHERE token_hash = 'old-1'`,
		`INSERT INTO sessions (id, user_id, token_hash, created_at, auth_time, last_seen_at, idle_expires_at, expires_at, user_agent, ip_address)
			VALUES ('00000000-0000-4000-8000-0000000000b2', '` + userID + `', 'old-2', now(), now(), now(), now() + interval '1 hour', now() + interval '1 day', '', '')`,
		`INSERT INTO refresh_token_families (id, session_id, client_id, user_id, scope, oidc_scopes, created_at)
			VALUES ('00000000-0000-4000-8000-0000000000c2', '00000000-0000-4000-8000-0000000000b2', 'ui', '` + userID + `', 'demo:a:b', 'openid', now())`,
		`SELECT id, session_id, client_id, user_id, scope, oidc_scopes, created_at, revoked_at FROM refresh_token_families WHERE id = '00000000-0000-4000-8000-0000000000c2'`,
		`UPDATE sessions SET revoked_at = now() WHERE token_hash = 'old-2'`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("old SQL: %v\n%s", err, q)
		}
	}
	// The tables of the factors.
	if _, err := pool.Exec(ctx, `INSERT INTO user_totp (user_id, secret, key_id, created_at) VALUES ($1, '\x00', 'k', now())`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO user_totp (user_id, secret, key_id, created_at) VALUES ($1, '\x00', 'k', now())`, userID); err == nil {
		t.Fatal("a second TOTP row must fail")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES ('00000000-0000-4000-8000-0000000000d1', $1, '\x01', now())`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES ('00000000-0000-4000-8000-0000000000d2', $1, '\x01', now())`, userID); err == nil {
		t.Fatal("a duplicate code hash must fail")
	}
	down, err := migrations.Files.ReadFile("0012_mfa.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('user_totp', 'recovery_codes')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tables after the down: %d, %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE (table_name = 'sessions' AND column_name = 'amr') OR (table_name = 'refresh_token_families' AND column_name IN ('amr', 'auth_time'))`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("columns after the down: %d, %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("sessions after the down: %d, %v", n, err)
	}
}

func TestIssue14Integration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h, mfaOptions()...)
	demoRole := "demo:agent"

	// I2: the full setup.
	u2 := f.newTOTPUser("i2@example.com", demoRole)
	t.Run("I2_setup", func(t *testing.T) {
		var sealed []byte
		var keyID string
		if err := f.a.Pool(t).QueryRow(ctx, `SELECT secret, key_id FROM user_totp WHERE user_id = $1`, u2.id).Scan(&sealed, &keyID); err != nil {
			t.Fatal(err)
		}
		if len(sealed) < 40 || keyID != "test" || strings.Contains(string(sealed), u2.secret) {
			t.Fatalf("the stored secret is not an envelope: %d bytes, key %q", len(sealed), keyID)
		}
		tr := f.sessionToken(u2, "admin-ui", adminRedirect, mfaScope)
		st := f.mfaStatus(tr.AccessToken)
		totp, _ := st["totp"].(map[string]any)
		if st["enabled"] != true || st["required"] != false || st["recoveryCodesRemaining"] != float64(10) || totp["createdAt"] == nil {
			t.Fatalf("status = %v", st)
		}
		if _, has := totp["lastUsedAt"]; has {
			t.Fatal("lastUsedAt must be absent before a code is used")
		}
		// The page of the account.
		resp, body := u2.web.Get(t, "/account/security")
		status(t, resp, http.StatusOK, "GET /account/security")
		if !strings.Contains(string(body), "Recovery codes left: 10") || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("security page: %s", body)
		}
		// A second setup goes back to the status page.
		resp, _ = u2.web.Get(t, "/account/totp")
		status(t, resp, http.StatusSeeOther, "GET /account/totp with TOTP on")
	})

	// I3: the code flow with TOTP.
	t.Run("I3_code_flow", func(t *testing.T) {
		u := f.newTOTPUser("i3@example.com", demoRole)
		web := f.a.NewWeb()
		browser := &mfaUser{id: u.id, email: u.email, web: web, secret: u.secret, password: u.password}
		tr := f.mfaToken(browser, "admin-ui", adminRedirect, mfaScope, nil)
		if got := amrOf(t, tr.AccessToken); got != "pwd otp mfa" {
			t.Fatalf("access token amr = %q", got)
		}
		if got := amrOf(t, tr.IDToken); got != "pwd otp mfa" {
			t.Fatalf("ID token amr = %q", got)
		}
		at, it := authTimeOf(t, tr.AccessToken), authTimeOf(t, tr.IDToken)
		if at == 0 || at != it || int64(at) != f.clock.Now().Unix()-0 && time.Unix(int64(at), 0).After(f.clock.Now()) {
			t.Fatalf("auth_time access %v id %v", at, it)
		}
		st := f.mfaStatus(tr.AccessToken)
		totp, _ := st["totp"].(map[string]any)
		if totp["lastUsedAt"] == nil {
			t.Fatalf("lastUsedAt must be set: %v", st)
		}
	})

	// I4: a refresh keeps the amr and the auth_time of the original login.
	t.Run("I4_refresh_keeps_login", func(t *testing.T) {
		u := f.newTOTPUser("i4@example.com", demoRole)
		web := f.a.NewWeb()
		browser := &mfaUser{id: u.id, email: u.email, web: web, secret: u.secret, password: u.password}
		first := f.mfaToken(browser, "admin-ui", adminRedirect, mfaOfflineFlow, nil)
		time1 := authTimeOf(t, first.AccessToken)
		resp, r1 := f.a.TokenRequest(t, testserver.RefreshForm("admin-ui", first.RefreshToken))
		status(t, resp, http.StatusOK, "refresh")
		if amrOf(t, r1.AccessToken) != "pwd otp mfa" || authTimeOf(t, r1.AccessToken) != time1 {
			t.Fatalf("refreshed token: amr %q auth_time %v want %v", amrOf(t, r1.AccessToken), authTimeOf(t, r1.AccessToken), time1)
		}
		// 10 minutes later, a step-up in a second client with the same session.
		f.advance(10 * time.Minute)
		p := testserver.NewPKCE(t)
		f.startMFALogin(web, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, map[string]string{"prompt": "login"}), u.email, u.password)
		loc := f.finishMFALogin(web, testserver.TOTPCode(t, u.secret, f.clock.Now()), false)
		second := f.exchangeCode(loc, p, "demo-ui", demoRedirect)
		time2 := authTimeOf(t, second.AccessToken)
		if time2 <= time1 || amrOf(t, second.AccessToken) != "pwd otp mfa" {
			t.Fatalf("second client: auth_time %v (first %v), amr %q", time2, time1, amrOf(t, second.AccessToken))
		}
		resp, r2 := f.a.TokenRequest(t, testserver.RefreshForm("admin-ui", r1.RefreshToken))
		status(t, resp, http.StatusOK, "refresh after the step-up")
		if authTimeOf(t, r2.AccessToken) != time1 || amrOf(t, r2.AccessToken) != "pwd otp mfa" {
			t.Fatalf("the first client must keep its auth_time: %v want %v", authTimeOf(t, r2.AccessToken), time1)
		}
	})

	// I5: a recovery code works one time.
	t.Run("I5_recovery_code", func(t *testing.T) {
		u := f.newTOTPUser("i5@example.com", demoRole)
		web := f.a.NewWeb()
		browser := &mfaUser{id: u.id, email: u.email, web: web, secret: u.secret, password: u.password}
		p := testserver.NewPKCE(t)
		f.startMFALogin(web, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, p, nil), u.email, u.password)
		loc := f.finishMFALogin(web, u.codes[0], true)
		tr := f.exchangeCode(loc, p, "admin-ui", adminRedirect)
		if got := amrOf(t, tr.AccessToken); got != "pwd rec mfa" {
			t.Fatalf("amr = %q", got)
		}
		if st := f.mfaStatus(tr.AccessToken); st["recoveryCodesRemaining"] != float64(9) {
			t.Fatalf("status = %v", st)
		}
		// The same code again is refused.
		web2 := f.a.NewWeb()
		f.startMFALogin(web2, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, testserver.NewPKCE(t), nil), u.email, u.password)
		resp, _ := web2.PostForm(t, "/login/mfa", url.Values{"code": {u.codes[0]}, "recovery": {"1"}})
		status(t, resp, http.StatusUnauthorized, "a used recovery code")
		_ = browser
	})

	// I6: the pending login of user A does not take a code of user B.
	t.Run("I6_other_user_code", func(t *testing.T) {
		a := f.newTOTPUser("i6a@example.com", demoRole)
		b := f.newTOTPUser("i6b@example.com", demoRole)
		web := f.a.NewWeb()
		f.advance(31 * time.Second)
		f.startMFALogin(web, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, testserver.NewPKCE(t), nil), a.email, a.password)
		resp, _ := web.PostForm(t, "/login/mfa", url.Values{"code": {testserver.TOTPCode(t, b.secret, f.clock.Now())}})
		status(t, resp, http.StatusUnauthorized, "a code of another user")
		if f.countWhere(`SELECT count(*) FROM sessions WHERE user_id = $1 AND token_hash = encode(sha256($2::bytea), 'hex')`, a.id, web.Cookie(pages.CookieName)) != 0 {
			t.Fatal("no session may exist")
		}
	})

	// I7: no pending cookie, and a pending login that expired.
	t.Run("I7_no_pending", func(t *testing.T) {
		web := f.a.NewWeb()
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			var resp testserver.Response
			if method == http.MethodGet {
				resp, _ = web.Get(t, "/login/mfa")
			} else {
				resp, _ = web.PostForm(t, "/login/mfa", url.Values{"code": {"123456"}})
			}
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
				t.Fatalf("%s without a pending login: %d %s", method, resp.StatusCode, resp.Header.Get("Location"))
			}
		}
		u := f.newTOTPUser("i7@example.com", demoRole)
		f.advance(31 * time.Second)
		web = f.a.NewWeb()
		f.startMFALogin(web, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, testserver.NewPKCE(t), nil), u.email, u.password)
		f.advance(6 * time.Minute)
		resp, _ := web.PostForm(t, "/login/mfa", url.Values{"code": {testserver.TOTPCode(t, u.secret, f.clock.Now())}})
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Fatalf("expired pending login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	// I8: 11 bad codes over three pending logins for one user. The eleventh gets 429.
	t.Run("I8_failure_counter", func(t *testing.T) {
		u := f.newTOTPUser("i8@example.com", demoRole)
		sent := 0
		for _, n := range []int{4, 4, 3} {
			web := f.a.NewWeb()
			f.startMFALogin(web, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, testserver.NewPKCE(t), nil), u.email, u.password)
			for i := 0; i < n; i++ {
				resp, _ := web.PostForm(t, "/login/mfa", url.Values{"code": {"000000"}})
				sent++
				want := http.StatusUnauthorized
				if sent == 11 {
					want = http.StatusTooManyRequests
				}
				status(t, resp, want, "bad code number "+string(rune('0'+sent/10))+string(rune('0'+sent%10)))
			}
		}
	})

	// I13: the removal of TOTP with a fresh token.
	t.Run("I13_remove_totp", func(t *testing.T) {
		u := f.newTOTPUser("i13@example.com", demoRole)
		tr := f.sessionToken(u, "admin-ui", adminRedirect, mfaScope)
		resp, m := f.api(tr.AccessToken, http.MethodDelete, "/v1/me/totp", nil)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove: %d %v", resp.StatusCode, m)
		}
		st := f.mfaStatus(tr.AccessToken)
		if _, has := st["totp"]; has || st["enabled"] != false || st["recoveryCodesRemaining"] != float64(0) {
			t.Fatalf("status = %v", st)
		}
		if f.countWhere(`SELECT count(*) FROM user_totp WHERE user_id = $1`, u.id)+f.countWhere(`SELECT count(*) FROM recovery_codes WHERE user_id = $1`, u.id) != 0 {
			t.Fatal("the rows must be gone")
		}
		// The next login asks for the password only.
		f.passwordLogin(f.a.NewWeb(), u.email, u.password, "/login/done")
		// The next call gives 404 totp_not_found.
		resp, m = f.api(tr.AccessToken, http.MethodDelete, "/v1/me/totp", nil)
		if resp.StatusCode != http.StatusNotFound || m["code"] != "totp_not_found" {
			t.Fatalf("second removal: %d %v", resp.StatusCode, m)
		}
	})

	// I12: the 401 refusal with a token whose auth_time is 6 minutes old.
	t.Run("I12_stale_token", func(t *testing.T) {
		u := f.newTOTPUser("i12@example.com", demoRole)
		tr := f.sessionToken(u, "admin-ui", adminRedirect, mfaScope)
		f.advance(6 * time.Minute)
		resp, b := f.a.Do(t, http.MethodDelete, "/v1/me/totp", tr.AccessToken, "")
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Content-Type") != "application/problem+json" ||
			resp.Header.Get("WWW-Authenticate") != `Bearer error="insufficient_user_authentication", error_description="A fresh MFA login is necessary", max_age="300"` ||
			!strings.Contains(string(b), `"code":"reauthentication_required"`) || !strings.Contains(string(b), `"title":"Reauthentication required"`) {
			t.Fatalf("stale token: %d %v %s", resp.StatusCode, resp.Header, b)
		}
		if f.countWhere(`SELECT count(*) FROM user_totp WHERE user_id = $1`, u.id) != 1 {
			t.Fatal("TOTP must stay")
		}
		// I27: the step-up. A new authorization request with max_age and prompt=login in the same session.
		p := testserver.NewPKCE(t)
		f.advance(31 * time.Second)
		f.startMFALogin(u.web, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, p, map[string]string{"max_age": "300", "prompt": "login"}), u.email, u.password)
		loc := f.finishMFALogin(u.web, testserver.TOTPCode(t, u.secret, f.clock.Now()), false)
		fresh := f.exchangeCode(loc, p, "admin-ui", adminRedirect)
		if authTimeOf(t, fresh.AccessToken) <= authTimeOf(t, tr.AccessToken) || amrOf(t, fresh.AccessToken) != "pwd otp mfa" {
			t.Fatalf("the new token must have a later auth_time and mfa")
		}
		if resp, m := f.api(fresh.AccessToken, http.MethodDelete, "/v1/me/totp", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove after the step-up: %d %v", resp.StatusCode, m)
		}
	})

	// I28: a step-up with the password only gives no fresh session.
	t.Run("I28_step_up_no_second_factor", func(t *testing.T) {
		u := f.newTOTPUser("i28@example.com", demoRole)
		tr := f.sessionToken(u, "admin-ui", adminRedirect, mfaScope)
		before := authTimeOf(t, tr.AccessToken)
		var methodsBefore []string
		var authBefore time.Time
		sid := f.sessionID(u.web)
		pool := f.a.Pool(t)
		if err := pool.QueryRow(ctx, `SELECT amr, auth_time FROM sessions WHERE id = $1`, sid).Scan(&methodsBefore, &authBefore); err != nil {
			t.Fatal(err)
		}
		f.advance(2 * time.Minute)
		p := testserver.NewPKCE(t)
		resp := u.web.Authorize(t, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, p, map[string]string{"prompt": "login"}))
		id := testserver.Location(t, resp).Query().Get("authRequest")
		resp, _ = u.web.PostForm(t, "/login", url.Values{"email": {u.email}, "password": {u.password}, "authRequest": {id}})
		status(t, resp, http.StatusSeeOther, "POST /login")
		// No POST /login/mfa. The continue step runs anyway.
		resp, _ = u.web.Get(t, "/oauth/authorize/continue?authRequest="+url.QueryEscape(id))
		loc := testserver.Location(t, resp)
		if loc.Query().Get("code") != "" {
			t.Fatalf("no code may be issued: %s", loc)
		}
		var methodsAfter []string
		var authAfter time.Time
		if err := pool.QueryRow(ctx, `SELECT amr, auth_time FROM sessions WHERE id = $1`, sid).Scan(&methodsAfter, &authAfter); err != nil {
			t.Fatal(err)
		}
		if !authAfter.Equal(authBefore) || !slices.Equal(methodsAfter, methodsBefore) || before == 0 {
			t.Fatalf("the session changed: %v %v -> %v %v", methodsBefore, authBefore, methodsAfter, authAfter)
		}
	})

	// I15, I30, I31, I32, I33: the reset of the MFA of a user.
	g := newFixture(t, h, mfaOptions(requireAdmins())...)
	gAdmin := g.newMFAAdmin()
	t.Run("I10_first_admin", func(t *testing.T) {
		// A new login of the admin (no second factor yet is not possible: TOTP is set up).
		// The session of the setup has [pwd] only. It gets no code before the setup.
		// Test it with a second admin, who has no factor.
		tok := g.adminMFAToken(gAdmin, adminMFAScopes)
		second := g.newUser(tok, "admin2@example.com", userPassword, "identity:admin")
		web := g.a.NewWeb()
		g.passwordLogin(web, "admin2@example.com", userPassword, "/account/totp?required=1")
		resp := web.Authorize(t, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, testserver.NewPKCE(t), nil))
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || loc != "/account/totp?required=1" {
			t.Fatalf("authorize with no factor: %d %s", resp.StatusCode, loc)
		}
		// After the setup, the code flow works with mfa, and the status has required true.
		secret, _ := g.setupTOTP(web)
		a2 := &mfaUser{id: second, email: "admin2@example.com", web: web, secret: secret, password: userPassword}
		access := g.sessionToken(a2, "admin-ui", adminRedirect, mfaScope+" identity:admin")
		if amrOf(t, access.AccessToken) != "pwd otp mfa" {
			t.Fatalf("amr = %q", amrOf(t, access.AccessToken))
		}
		if st := g.mfaStatus(access.AccessToken); st["required"] != true || st["enabled"] != true {
			t.Fatalf("status = %v", st)
		}
		// The removal of TOTP of an admin gives 409.
		resp2, m := g.api(access.AccessToken, http.MethodDelete, "/v1/me/totp", nil)
		if resp2.StatusCode != http.StatusConflict || m["code"] != "mfa_required" {
			t.Fatalf("remove for an admin: %d %v", resp2.StatusCode, m)
		}
		// The page gives the same refusal.
		resp, _ = web.PostForm(t, "/account/totp/remove", url.Values{})
		status(t, resp, http.StatusConflict, "POST /account/totp/remove for an admin")
	})

	// I11: an admin session and a refresh family from before the upgrade.
	t.Run("I11_before_the_upgrade", func(t *testing.T) {
		tr := g.mfaToken(gAdmin, "admin-ui", adminRedirect, "openid offline_access identity:mfa:manage_own", nil)
		sid := g.sessionID(gAdmin.web)
		pool := g.a.Pool(t)
		if _, err := pool.Exec(ctx, `UPDATE sessions SET amr = '{}' WHERE id = $1`, sid); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE refresh_token_families SET auth_time = NULL, amr = '{}' WHERE session_id = $1`, sid); err != nil {
			t.Fatal(err)
		}
		resp, r := g.a.TokenRequest(t, testserver.RefreshForm("admin-ui", tr.RefreshToken))
		if resp.StatusCode != http.StatusBadRequest || r.Error != "invalid_grant" {
			t.Fatalf("refresh: %d %+v", resp.StatusCode, r)
		}
		resp = gAdmin.web.Authorize(t, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, testserver.NewPKCE(t), nil))
		if loc := testserver.Location(t, resp); !strings.HasPrefix(loc.Path, "/login") || loc.Query().Get("authRequest") == "" {
			t.Fatalf("authorize: %s", loc)
		}
	})

	// U13 (live form): a refresh of an admin whose family has no mfa gives invalid_grant.
	// The family of I11 covers it. This case makes the family with [pwd] only.
	t.Run("U13_refresh_admin_without_mfa", func(t *testing.T) {
		tr := g.mfaToken(gAdmin, "admin-ui", adminRedirect, "openid offline_access identity:mfa:manage_own", nil)
		if _, err := g.a.Pool(t).Exec(ctx, `UPDATE refresh_token_families SET amr = '{pwd}'`); err != nil {
			t.Fatal(err)
		}
		resp, r := g.a.TokenRequest(t, testserver.RefreshForm("admin-ui", tr.RefreshToken))
		if resp.StatusCode != http.StatusBadRequest || r.Error != "invalid_grant" {
			t.Fatalf("refresh: %d %+v", resp.StatusCode, r)
		}
	})

	// U11, U12: the authorization of an admin with a [pwd] session and no factor, rule on and off.
	t.Run("U11_U12_authorize_rule", func(t *testing.T) {
		off := newFixture(t, h, mfaOptions()...)
		web := off.a.NewWeb()
		off.passwordLogin(web, "admin@example.com", adminPassword, "/login/done")
		resp := web.Authorize(t, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope+" identity:admin", testserver.NewPKCE(t), nil))
		if loc := testserver.Location(t, resp); loc.Query().Get("code") == "" {
			t.Fatalf("rule off: no code in %s", loc)
		}
	})

	// I15, I30, I31, I32, I33: the reset of the MFA.
	t.Run("I15_reset", func(t *testing.T) {
		f2 := g
		tok := f2.adminMFAToken(gAdmin, adminMFAScopes)
		id := f2.newUser(tok, "i15@example.com", userPassword, "demo:agent")
		web1, web2 := f2.a.NewWeb(), f2.a.NewWeb()
		f2.passwordLogin(web1, "i15@example.com", userPassword, "/login/done")
		secret, _ := f2.setupTOTP(web1)
		u := &mfaUser{id: id, email: "i15@example.com", web: web1, secret: secret, password: userPassword}
		first := f2.sessionToken(u, "admin-ui", adminRedirect, "openid offline_access identity:mfa:manage_own identity:api_token:manage_own")
		u2 := &mfaUser{id: id, email: u.email, web: web2, secret: secret, password: userPassword}
		second := f2.mfaToken(u2, "admin-ui", adminRedirect, "openid offline_access identity:mfa:manage_own", nil)
		resp, m := f2.api(first.AccessToken, http.MethodPost, "/v1/me/api-tokens", map[string]any{"name": "t", "scope": "demo:ticket:read"})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("api token: %d %v", resp.StatusCode, m)
		}
		// I31: UserMfa_get.
		resp, m = f2.api(tok, http.MethodGet, "/v1/users/"+id+"/mfa", nil)
		totp, _ := m["totp"].(map[string]any)
		if resp.StatusCode != http.StatusOK || m["enabled"] != true || totp["createdAt"] == nil || m["recoveryCodesRemaining"] != float64(10) {
			t.Fatalf("UserMfa_get: %d %v", resp.StatusCode, m)
		}
		// I32, I33: unknown user and a token without identity:mfa:read.
		unknown := "00000000-0000-4000-8000-0000000000ee"
		if resp, m = f2.api(tok, http.MethodGet, "/v1/users/"+unknown+"/mfa", nil); resp.StatusCode != http.StatusNotFound || m["code"] != "user_not_found" {
			t.Fatalf("UserMfa_get unknown: %d %v", resp.StatusCode, m)
		}
		if resp, m = f2.api(tok, http.MethodDelete, "/v1/users/"+unknown+"/mfa", nil); resp.StatusCode != http.StatusNotFound || m["code"] != "user_not_found" {
			t.Fatalf("UserMfa_reset unknown: %d %v", resp.StatusCode, m)
		}
		noRead := f2.adminMFAToken(gAdmin, "openid identity:user:read")
		if resp, _ = f2.api(noRead, http.MethodGet, "/v1/users/"+id+"/mfa", nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("UserMfa_get without identity:mfa:read: %d", resp.StatusCode)
		}
		// I15: the reset.
		resp, m = f2.api(tok, http.MethodDelete, "/v1/users/"+id+"/mfa", nil)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("reset: %d %v", resp.StatusCode, m)
		}
		if f2.countWhere(`SELECT count(*) FROM user_totp WHERE user_id = $1`, id)+f2.countWhere(`SELECT count(*) FROM recovery_codes WHERE user_id = $1`, id) != 0 {
			t.Fatal("the factors must be gone")
		}
		if f2.countWhere(`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, id) != 0 {
			t.Fatal("the sessions must be revoked")
		}
		for _, rt := range []string{first.RefreshToken, second.RefreshToken} {
			if resp, r := f2.a.TokenRequest(t, testserver.RefreshForm("admin-ui", rt)); resp.StatusCode != http.StatusBadRequest || r.Error != "invalid_grant" {
				t.Fatalf("refresh after the reset: %d %+v", resp.StatusCode, r)
			}
		}
		if f2.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL`, id) != 1 {
			t.Fatal("the API token must stay active")
		}
		f2.passwordLogin(f2.a.NewWeb(), u.email, userPassword, "/login/done")
		// I30: a reset for a user with no factor and one session gives 204 and revokes the session.
		if resp, _ = f2.api(tok, http.MethodDelete, "/v1/users/"+id+"/mfa", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("reset with no factor: %d", resp.StatusCode)
		}
		if f2.countWhere(`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, id) != 0 {
			t.Fatal("the session must be revoked")
		}
		// I35: a reset of the own MFA gives 409.
		resp, m = f2.api(tok, http.MethodDelete, "/v1/users/"+gAdmin.id+"/mfa", nil)
		if resp.StatusCode != http.StatusConflict || m["code"] != "mfa_required" {
			t.Fatalf("self reset: %d %v", resp.StatusCode, m)
		}
		if f2.countWhere(`SELECT count(*) FROM user_totp WHERE user_id = $1`, gAdmin.id) != 1 {
			t.Fatal("the TOTP of the admin must stay")
		}
		// I40: the audit entries and the notices are in the log.
		var audits, notices int
		for _, r := range f2.a.logs.Records(t) {
			switch r["msg"] {
			case "identity.audit":
				if r["action"] == "identity:mfa:reset" && r["target_user_id"] == id && r["actor"] == gAdmin.id && r["result"] == "success" {
					audits++
				}
			case "identity.security_notice":
				if r["kind"] == "mfa_reset" && r["target_user_id"] == id {
					notices++
				}
			}
		}
		if audits != 2 || notices != 2 {
			t.Fatalf("audit records = %d, notice records = %d, want 2 each", audits, notices)
		}
	})

	// I17, I37: the subcommand reset-mfa for the last admin.
	t.Run("I17_reset_mfa_subcommand", func(t *testing.T) {
		if err := services.ResetMFA(ctx, g.a.Config, "admin@example.com", g.a.logs.Logger()); err != nil {
			t.Fatal(err)
		}
		if err := services.ResetMFA(ctx, g.a.Config, "nobody@example.com", g.a.logs.Logger()); err == nil {
			t.Fatal("an unknown email must fail")
		}
		web := g.a.NewWeb()
		g.passwordLogin(web, "admin@example.com", adminPassword, "/account/totp?required=1")
		found := false
		for _, r := range g.a.logs.Records(t) {
			if r["msg"] == "identity.audit" && r["action"] == "identity:mfa:reset" && r["actor"] == "cli" && r["target_user_id"] == gAdmin.id {
				found = true
			}
		}
		if !found {
			t.Fatal("no audit record of the subcommand")
		}
	})

	// I18: the bucket mfa_verify.
	t.Run("I18_rate_limit", func(t *testing.T) {
		vkRL := containers.Valkey(t, containers.WithValkeyImage(testserver.ValkeyImage))
		hl := &harness{env: &testserver.Env{PG: h.env.PG, VK: vkRL}, ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
		lim := newFixture(t, hl, mfaOptions(testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketMFAVerify: {Limit: 2, Window: time.Minute}}))...)
		web := lim.a.NewWeb()
		for i, want := range []int{http.StatusSeeOther, http.StatusSeeOther, http.StatusTooManyRequests} {
			resp, _ := web.PostForm(t, "/login/mfa", url.Values{"code": {"123456"}})
			if resp.StatusCode != want {
				t.Fatalf("request %d: %d, want %d", i+1, resp.StatusCode, want)
			}
		}
		// A GET of the page does not count.
		if resp, _ := web.Get(t, "/login/mfa"); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("GET: %d", resp.StatusCode)
		}
	})

	// I20: the master key changes, the previous key stays. A login with TOTP works.
	t.Run("I20_master_key_rotation", func(t *testing.T) {
		old := testserver.MasterKey(t)
		r := newFixture(t, &harness{env: h.env, ledger: h.ledger, masterKey: old}, mfaOptions()...)
		u := r.newTOTPUser("i20@example.com", demoRole)
		r.advance(31 * time.Second)
		s2 := h.env.Start(t, testserver.WithDB(r.a.DB), testserver.WithMasterKey(testserver.MasterKey(t), "second"),
			testserver.WithClock(r.clock), testserver.WithClockedVerifier(), testserver.WithCORSCacheTTL(0),
			testserver.WithConfigure(func(c *config.Config) { c.Secrets.PreviousKeys = platformconfig.Secret("test:" + old) }))
		web := s2.NewWeb()
		resp, _ := web.PostForm(t, "/login", url.Values{"email": {u.email}, "password": {u.password}})
		status(t, resp, http.StatusSeeOther, "POST /login")
		resp, _ = web.PostForm(t, "/login/mfa", url.Values{"code": {testserver.TOTPCode(t, u.secret, r.clock.Now())}})
		status(t, resp, http.StatusSeeOther, "POST /login/mfa after the key change")
		if got := resp.Header.Get("Location"); got != "/login/done" {
			t.Fatalf("Location = %q", got)
		}
	})

	// I9: Valkey stops during the second factor.
	t.Run("I9_valkey_down", func(t *testing.T) {
		vk := containers.Valkey(t, containers.WithValkeyImage(testserver.ValkeyImage))
		hv := &harness{env: &testserver.Env{PG: h.env.PG, VK: vk}, ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
		v := newFixture(t, hv, mfaOptions()...)
		u := v.newTOTPUser("i9@example.com", demoRole)
		web := v.a.NewWeb()
		v.advance(31 * time.Second)
		v.startMFALogin(web, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, testserver.NewPKCE(t), nil), u.email, u.password)
		sessions := v.countWhere(`SELECT count(*) FROM sessions`)
		if err := vk.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		resp, _ := web.PostForm(t, "/login/mfa", url.Values{"code": {testserver.TOTPCode(t, u.secret, v.clock.Now())}})
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("POST /login/mfa with Valkey down: %d", resp.StatusCode)
		}
		if v.countWhere(`SELECT count(*) FROM sessions`) != sessions {
			t.Fatal("no session may be made")
		}
	})

	// I29, I39: the upgrade. The previous version has no MFA keys. The start of the
	// new version on the same database gives the roles the new keys.
	t.Run("I29_upgrade_role_permissions", func(t *testing.T) {
		up := newFixture(t, h, mfaOptions()...)
		pool := up.a.Pool(t)
		if _, err := pool.Exec(ctx, `DELETE FROM permissions WHERE key LIKE 'identity:mfa:%'`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE apps SET manifest_hash = 'previous' WHERE key = 'identity'`); err != nil {
			t.Fatal(err)
		}
		s2 := h.env.Start(t, testserver.WithDB(up.a.DB), testserver.WithMasterKey(h.masterKey, "test"),
			testserver.WithClock(up.clock), testserver.WithClockedVerifier(), testserver.WithCORSCacheTTL(0),
			testserver.WithClientsFile(up.a.Config.ClientsFile))
		held := func(role string) []string {
			rows, err := pool.Query(ctx, `SELECT permission FROM role_permissions WHERE app = 'identity' AND role = $1 AND permission LIKE 'identity:mfa:%' ORDER BY permission`, role)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var out []string
			for rows.Next() {
				var p string
				if err := rows.Scan(&p); err != nil {
					t.Fatal(err)
				}
				out = append(out, p)
			}
			return out
		}
		if got := held("admin"); !slices.Equal(got, []string{"identity:mfa:manage_own", "identity:mfa:read", "identity:mfa:reset"}) {
			t.Fatalf("admin permissions = %v", got)
		}
		if got := held("user"); !slices.Equal(got, []string{"identity:mfa:manage_own"}) {
			t.Fatalf("user permissions = %v", got)
		}
		// A user logs in with the scope of the new key and calls MeMfa_get.
		web := s2.NewWeb()
		up.a.ledger.add(&up.a.ledger.passwords, adminPassword)
		p := testserver.NewPKCE(t)
		loc := web.CodeFlow(t, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, p, nil), "admin@example.com", adminPassword)
		code := loc.Query().Get("code")
		resp, tr := s2.TokenRequest(t, testserver.CodeForm("admin-ui", code, adminRedirect, p.Verifier))
		status(t, resp, http.StatusOK, "token")
		resp, _ = s2.Do(t, http.MethodGet, "/v1/me/mfa", tr.AccessToken, "")
		status(t, resp, http.StatusOK, "MeMfa_get after the upgrade")
	})

	// I19: no log record and no span holds a TOTP secret, a recovery code, or the
	// value of a pending login.
	t.Run("I19_no_secrets_in_telemetry", func(t *testing.T) {
		h.ledger.mu.Lock()
		defer h.ledger.mu.Unlock()
		if len(h.ledger.flow) < 100 {
			t.Fatalf("the ledger has %d values", len(h.ledger.flow))
		}
		var texts []string
		for _, l := range h.ledger.logs {
			texts = append(texts, l.Text())
		}
		spans := ""
		for _, s := range spanExporter.GetSpans() {
			spans += s.Name + "\n"
			for _, a := range s.Attributes {
				spans += string(a.Key) + "=" + a.Value.String() + "\n"
			}
			for _, e := range s.Events {
				for _, a := range e.Attributes {
					spans += string(a.Key) + "=" + a.Value.String() + "\n"
				}
			}
		}
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
		for _, text := range texts {
			if strings.Contains(text, "otpauth://") {
				t.Fatal("a log record holds an otpauth URI")
			}
		}
	})
}
