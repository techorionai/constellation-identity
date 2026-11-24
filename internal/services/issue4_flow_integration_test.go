//go:build integration

package services_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/auth/jwt"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

const userPass2 = "agent password 5521 long"

// redirectError checks that a response redirects to the redirect URI with an
// error and the state.
func redirectError(t *testing.T, resp testserver.Response, want string) {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want a redirect with %s", resp.StatusCode, want)
	}
	q := testserver.Location(t, resp).Query()
	if q.Get("error") != want {
		t.Fatalf("error = %q, want %q (location %s)", q.Get("error"), want, resp.Header.Get("Location"))
	}
}

// codeOf returns the code of a redirect.
func codeOf(t *testing.T, loc *url.URL) string {
	t.Helper()
	c := loc.Query().Get("code")
	if c == "" {
		t.Fatalf("no code in %s", loc)
	}
	return c
}

func TestIssue4CodeFlowIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h)
	admin := f.adminToken(adminScopes)
	f.newUser(admin, "agent@example.com", userPass2, "demo:agent")
	f.newUser(admin, "norole@example.com", userPass2)

	// I1, I1a, I2: the full flow.
	t.Run("I1_I2_full_flow", func(t *testing.T) {
		tr, web := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, "openid email offline_access demo:ticket:read demo:ticket:write foo identity:admin")
		if tr.TokenType != "Bearer" || tr.RefreshToken == "" || tr.IDToken == "" {
			t.Fatalf("response = %+v", tr)
		}
		// demo:agent has demo:ticket:read only. The service drops the rest.
		if tr.Scope != "demo:ticket:read" || tr.ExpiresIn != 900 {
			t.Fatalf("scope = %q, expires_in = %d", tr.Scope, tr.ExpiresIn)
		}
		hdr, claims := testserver.JWTClaims(t, tr.AccessToken)
		if hdr["typ"] != "at+jwt" || claims["aud"] != "demo" || claims["principal_type"] != "user" || claims["scope"] != "demo:ticket:read" {
			t.Fatalf("access token = %v %v", hdr, claims)
		}
		ih, ic := testserver.JWTClaims(t, tr.IDToken)
		if ih["typ"] != "JWT" || ic["nonce"] != "nonce-1" || ic["aud"] != "demo-ui" || ic["email"] != "agent@example.com" || ic["sid"] != f.sessionID(web) {
			t.Fatalf("id token = %v %v", ih, ic)
		}
		if _, ok := ic["name"]; ok {
			t.Fatal("the ID token has no name without the scope profile")
		}
		v, err := jwt.New(jwtConfig(f.a.Server, "demo"))
		if err != nil {
			t.Fatal(err)
		}
		if p, err := v.Verify(ctx, tr.AccessToken); err != nil || !slices.Equal(p.Scopes, []string{"demo:ticket:read"}) {
			t.Fatalf("verify demo: %v %+v", err, p)
		}
		other, err := jwt.New(jwtConfig(f.a.Server, "other"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.Verify(ctx, tr.AccessToken); err == nil {
			t.Fatal("the audience other must be rejected")
		}
		// I1a: no offline_access and no profile.
		tr2, _ := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, "openid demo:ticket:read")
		if tr2.RefreshToken != "" {
			t.Fatal("no refresh token without offline_access")
		}
		_, ic2 := testserver.JWTClaims(t, tr2.IDToken)
		if _, ok := ic2["name"]; ok {
			t.Fatal("no name without profile")
		}
		_, ic3 := testserver.JWTClaims(t, f.codeIDToken("agent@example.com", "openid profile demo:ticket:read"))
		if ic3["name"] != "User agent@example.com" {
			t.Fatalf("name = %v", ic3["name"])
		}
	})

	// I3, I3e, I3f, I3g, I26: the use of a code.
	t.Run("I3_code_reuse", func(t *testing.T) {
		web := f.a.NewWeb()
		p := testserver.NewPKCE(t)
		q := testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, nil)
		code := codeOf(t, web.CodeFlow(t, q, "agent@example.com", userPass2))
		// A wrong verifier does not use the code. The right verifier does.
		_, tr := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, testserver.NewPKCE(t).Verifier))
		if tr.Error != "invalid_grant" {
			t.Fatalf("wrong verifier: %+v", tr)
		}
		if n := f.countWhere(`SELECT count(*) FROM refresh_token_families WHERE session_id = $1`, f.sessionID(web)); n != 0 {
			t.Fatalf("families after a failed check = %d", n)
		}
		resp, ok := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, p.Verifier))
		if resp.StatusCode != http.StatusOK || ok.RefreshToken == "" {
			t.Fatalf("right verifier: %d %+v", resp.StatusCode, ok)
		}
		// I3g: a used code with a wrong verifier changes nothing.
		_, bad := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, testserver.NewPKCE(t).Verifier))
		if bad.Error != "invalid_grant" || f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NULL`, f.sessionID(web)) != 1 {
			t.Fatalf("wrong verifier after use: %+v", bad)
		}
		// I26: another client ID with the right verifier changes nothing.
		_, other := f.a.TokenRequest(t, testserver.CodeForm("loopback-ui", code, demoRedirect, p.Verifier))
		if other.Error != "invalid_grant" || f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NULL`, f.sessionID(web)) != 1 {
			t.Fatalf("other client: %+v", other)
		}
		if f.countWhere(`SELECT count(*) FROM refresh_token_families WHERE revoked_at IS NULL AND session_id = $1`, f.sessionID(web)) != 1 {
			t.Fatal("the family must stay valid")
		}
		// I3: the same client and the right verifier is a reuse.
		_, reuse := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, p.Verifier))
		if reuse.Error != "invalid_grant" {
			t.Fatalf("reuse: %+v", reuse)
		}
		if f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NOT NULL`, f.sessionID(web)) != 1 ||
			f.countWhere(`SELECT count(*) FROM refresh_token_families WHERE revoked_at IS NULL AND session_id = $1`, f.sessionID(web)) != 0 {
			t.Fatal("a code reuse must revoke the session and its families")
		}
		if _, r := f.a.TokenRequest(t, testserver.RefreshForm("demo-ui", ok.RefreshToken)); r.Error != "invalid_grant" {
			t.Fatalf("refresh after the reuse: %+v", r)
		}
		var warn bool
		for _, r := range f.a.logs.Records(t) {
			if r["event"] == "identity.code.reuse" && r["level"] == "WARN" && r["session_id"] != nil && r["client_id"] == "demo-ui" {
				warn = true
			}
		}
		if !warn {
			t.Fatal("no warn record for the code reuse")
		}
	})

	t.Run("I3e_reuse_without_family", func(t *testing.T) {
		web := f.a.NewWeb()
		p := testserver.NewPKCE(t)
		q := testserver.AuthorizeQuery("demo-ui", demoRedirect, "openid demo:ticket:read", p, nil)
		code := codeOf(t, web.CodeFlow(t, q, "agent@example.com", userPass2))
		if resp, _ := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, p.Verifier)); resp.StatusCode != http.StatusOK {
			t.Fatalf("first use: %d", resp.StatusCode)
		}
		if _, r := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, p.Verifier)); r.Error != "invalid_grant" {
			t.Fatalf("second use: %+v", r)
		}
		if f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NOT NULL`, f.sessionID(web)) != 1 {
			t.Fatal("the session must be revoked")
		}
	})

	// I3a, I3b, I3c, I3d, I23e, I23f: the checks of the token request.
	t.Run("I3_checks", func(t *testing.T) {
		web := f.a.NewWeb()
		p := testserver.NewPKCE(t)
		code := func() string {
			return codeOf(t, web.CodeFlow(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, nil), "agent@example.com", userPass2))
		}
		c := code()
		for name, form := range map[string]url.Values{
			"client":   testserver.CodeForm("loopback-ui", c, demoRedirect, p.Verifier),
			"redirect": testserver.CodeForm("demo-ui", c, "https://demo.example.com/other", p.Verifier),
			"verifier": testserver.CodeForm("demo-ui", c, demoRedirect, "short"),
			"none":     testserver.CodeForm("demo-ui", c, demoRedirect, ""),
		} {
			if _, r := f.a.TokenRequest(t, form); r.Error != "invalid_grant" || r.AccessToken != "" {
				t.Fatalf("%s: %+v", name, r)
			}
		}
		// None of these failed checks used the code.
		if resp, _ := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", c, demoRedirect, p.Verifier)); resp.StatusCode != http.StatusOK {
			t.Fatalf("the code must work after failed checks: %d", resp.StatusCode)
		}
		// I23e: a service client at the authorization_code grant.
		if resp, r := f.a.TokenRequest(t, testserver.CodeForm("demo", c, demoRedirect, p.Verifier)); resp.StatusCode != http.StatusUnauthorized || r.Error != "invalid_client" {
			t.Fatalf("service client: %d %+v", resp.StatusCode, r)
		}
		// I23f: a public client at the client_credentials grant.
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"demo-ui"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {"x.y.z"}}
		if resp, r := f.a.TokenRequest(t, form); resp.StatusCode != http.StatusUnauthorized || r.Error != "invalid_client" {
			t.Fatalf("public client credentials: %d %+v", resp.StatusCode, r)
		}
		// U11: a secret or a Basic header is invalid_request for each grant.
		for _, grant := range []url.Values{testserver.CodeForm("demo-ui", c, demoRedirect, p.Verifier), testserver.RefreshForm("demo-ui", "x")} {
			withSecret := url.Values(grant)
			withSecret.Set("client_secret", "s")
			if _, r := f.a.TokenRequest(t, withSecret); r.Error != "invalid_request" {
				t.Fatalf("secret: %+v", r)
			}
			withSecret.Del("client_secret")
			resp, _ := f.a.PostTokenAuthorization(t, withSecret, "Basic dGVzdDp0ZXN0")
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("Basic: %d", resp.StatusCode)
			}
		}
	})

	// I3d: the code lifetime.
	t.Run("I3d_code_ttl", func(t *testing.T) {
		f2 := newFixture(t, h, testserver.WithConfigure(func(c *config.Config) { c.OIDC.CodeTTL = time.Second }))
		p := testserver.NewPKCE(t)
		loc := f2.admin.CodeFlow(t, testserver.AuthorizeQuery("admin-ui", adminRedirect, "openid identity:user:read", p, nil), "admin@example.com", adminPassword)
		code := codeOf(t, loc)
		time.Sleep(1500 * time.Millisecond)
		if _, r := f2.a.TokenRequest(t, testserver.CodeForm("admin-ui", code, adminRedirect, p.Verifier)); r.Error != "invalid_grant" {
			t.Fatalf("expired code: %+v", r)
		}
	})

	// I4a to I4i, I23a, I23b: the authorization request.
	t.Run("I4_authorize_errors", func(t *testing.T) {
		web := f.a.NewWeb()
		p := testserver.NewPKCE(t)
		base := func(extra map[string]string) url.Values {
			return testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, extra)
		}
		// I4a, I4h, I23e: an error page and no redirect.
		for name, q := range map[string]url.Values{
			"unregistered redirect": base(map[string]string{"redirect_uri": "https://evil.example.com/cb"}),
			"trailing slash":        base(map[string]string{"redirect_uri": demoRedirect + "/"}),
			"no client":             base(map[string]string{"client_id": ""}),
			"no redirect":           base(map[string]string{"redirect_uri": ""}),
			"unknown client":        base(map[string]string{"client_id": "nobody"}),
			"service client":        base(map[string]string{"client_id": "demo"}),
		} {
			resp := web.Authorize(t, q)
			if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
				t.Fatalf("%s: %d %q", name, resp.StatusCode, resp.Header.Get("Location"))
			}
		}
		// I4b, I4g, I4i: a redirect with invalid_request and the state.
		for name, extra := range map[string]map[string]string{
			"no challenge": {"code_challenge": ""}, "plain": {"code_challenge_method": "plain"}, "no scope": {"scope": ""},
			"no response_type": {"response_type": ""}, "no method": {"code_challenge_method": ""}, "token": {"response_type": "token"},
			"short challenge": {"code_challenge": "abc"}, "plus": {"code_challenge": strings.Repeat("+", 43)},
			"no nonce": {"nonce": ""}, "none and login": {"prompt": "none login"}, "max_age -1": {"max_age": "-1"}, "max_age x": {"max_age": "x"},
		} {
			resp := web.Authorize(t, base(extra))
			redirectError(t, resp, "invalid_request")
			if testserver.Location(t, resp).Query().Get("state") != "state-1" {
				t.Fatalf("%s: no state", name)
			}
		}
		// No state: the redirect has no state.
		resp := web.Authorize(t, base(map[string]string{"state": ""}))
		redirectError(t, resp, "invalid_request")
		if testserver.Location(t, resp).Query().Has("state") {
			t.Fatal("the redirect must have no state")
		}
		// I4c: no permission scope.
		redirectError(t, web.Authorize(t, base(map[string]string{"scope": "openid email"})), "invalid_scope")
		redirectError(t, web.Authorize(t, base(map[string]string{"scope": "openid identity:admin"})), "invalid_scope")
		// I4d: prompt none with no session.
		redirectError(t, web.Authorize(t, base(map[string]string{"prompt": "none"})), "login_required")
		// I23a: prompt consent is ignored.
		resp = web.Authorize(t, base(map[string]string{"prompt": "consent"}))
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?authRequest=") {
			t.Fatalf("prompt consent: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	// I14, I24, I24a: the login page of an auth request.
	t.Run("I14_I24_login_page", func(t *testing.T) {
		web := f.a.NewWeb()
		p := testserver.NewPKCE(t)
		resp := web.Authorize(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, nil))
		id := testserver.Location(t, resp).Query().Get("authRequest")
		resp, body := web.Get(t, "/login?authRequest="+id)
		csp := resp.Header.Get("Content-Security-Policy")
		if resp.StatusCode != http.StatusOK || !strings.Contains(csp, "form-action 'self' https://demo.example.com;") || !strings.Contains(string(body), `value="`+id+`"`) {
			t.Fatalf("login page: %d %q", resp.StatusCode, csp)
		}
		// I24: a wrong password shows the page again with the same CSP.
		resp, body = web.PostForm(t, "/login", url.Values{"email": {"agent@example.com"}, "password": {"wrong password 1234"}, "authRequest": {id}})
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "https://demo.example.com") || !strings.Contains(string(body), id) {
			t.Fatalf("failed login: %d %q", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
		}
		// I24a: the default policy has no extra origin.
		resp, _ = web.Get(t, "/login")
		if csp := resp.Header.Get("Content-Security-Policy"); strings.Contains(csp, "demo.example.com") || !strings.Contains(csp, "form-action 'self';") {
			t.Fatalf("default CSP = %q", csp)
		}
		// I14: a lost or unknown auth request gives an error page.
		resp, _ = web.Get(t, "/login?authRequest=lost")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("lost auth request: %d", resp.StatusCode)
		}
		resp, _ = web.PostForm(t, "/login", url.Values{"email": {"agent@example.com"}, "password": {userPass2}, "authRequest": {"lost"}})
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("login with a lost auth request: %d", resp.StatusCode)
		}
		resp, _ = web.Get(t, resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("continue with a lost auth request: %d", resp.StatusCode)
		}
	})

	// I14: a Valkey data loss during a login. The auth request is lost.
	t.Run("I14_valkey_flush_during_login", func(t *testing.T) {
		web := f.a.NewWeb()
		p := testserver.NewPKCE(t)
		resp := web.Authorize(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, nil))
		id := testserver.Location(t, resp).Query().Get("authRequest")
		if id == "" {
			t.Fatal("no auth request")
		}
		resp, _ = web.Get(t, "/login?authRequest="+id)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login page: %d", resp.StatusCode)
		}
		admin := h.env.VK.Admin(t)
		if err := admin.Do(ctx, admin.B().Flushall().Build()).Error(); err != nil {
			t.Fatalf("flushall: %v", err)
		}
		f.a.ledger.add(&f.a.ledger.passwords, userPass2)
		resp, _ = web.PostForm(t, "/login", url.Values{"email": {"agent@example.com"}, "password": {userPass2}, "authRequest": {id}})
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("login after the flush: %d", resp.StatusCode)
		}
		// The continue step shows an error page and gives no code.
		resp, body := web.Get(t, resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusBadRequest || strings.Contains(resp.Header.Get("Location"), "code=") || len(body) == 0 {
			t.Fatalf("continue after the flush: %d", resp.StatusCode)
		}
		// The user can start again. The session of the login is valid.
		p2 := testserver.NewPKCE(t)
		resp = web.Authorize(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p2, nil))
		codeOf(t, testserver.Location(t, resp))
	})

	// I19, I19a, I19b: the continue step.
	t.Run("I19_continue", func(t *testing.T) {
		web := f.a.NewWeb()
		f.loginWith(web, "agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		p := testserver.NewPKCE(t)
		f.advance(time.Second)
		resp := web.Authorize(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, map[string]string{"prompt": "login"}))
		id := testserver.Location(t, resp).Query().Get("authRequest")
		if !strings.HasPrefix(resp.Header.Get("Location"), "/login?authRequest=") {
			t.Fatalf("prompt=login: %s", resp.Header.Get("Location"))
		}
		resp, _ = web.Get(t, "/oauth/authorize/continue?authRequest="+id)
		redirectError(t, resp, "login_required")
		resp, _ = web.Get(t, "/oauth/authorize/continue?authRequest="+id)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("second continue: %d", resp.StatusCode)
		}
		// I19b: prompt=login ends after one login, with one code.
		f.advance(time.Second)
		loc := web.CodeFlow(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, map[string]string{"prompt": "login"}), "agent@example.com", userPass2)
		codeOf(t, loc)
		// An auth_time equal to the time of the auth request passes the continue
		// step. The clock does not move between the request and the login.
		loc = web.CodeFlow(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, map[string]string{"prompt": "login"}), "agent@example.com", userPass2)
		codeOf(t, loc)
		// max_age=1 with a clock that moved 2 seconds.
		f.advance(2 * time.Second)
		before := f.sessionRow(web).AuthTime
		loc = web.CodeFlow(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, map[string]string{"max_age": "1"}), "agent@example.com", userPass2)
		// I4f: the new login gives a new auth_time in the sessions row and in the ID token.
		maxAgeCode := codeOf(t, loc)
		after := f.sessionRow(web).AuthTime
		if !after.After(before) {
			t.Fatalf("auth_time of the session = %s, want later than %s", after, before)
		}
		resp, tr := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", maxAgeCode, demoRedirect, p.Verifier))
		if resp.StatusCode != http.StatusOK || tr.IDToken == "" {
			t.Fatalf("token request after max_age: %d %s", resp.StatusCode, tr.Error)
		}
		_, idClaims := testserver.JWTClaims(t, tr.IDToken)
		if got, _ := idClaims["auth_time"].(float64); int64(got) != after.Unix() || int64(got) <= before.Unix() {
			t.Fatalf("auth_time of the ID token = %d, session = %d, before = %d", int64(got), after.Unix(), before.Unix())
		}
		// I23: prompt=none with a session that does not meet max_age.
		f.advance(2 * time.Second)
		redirectError(t, web.Authorize(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, map[string]string{"prompt": "none", "max_age": "1"})), "login_required")
		// I19a: a logged in browser gets the code at once.
		resp = web.Authorize(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, nil))
		codeOf(t, testserver.Location(t, resp))
	})

	// I13: the user with no role gets invalid_scope.
	t.Run("U3c_no_permission", func(t *testing.T) {
		web := f.a.NewWeb()
		p := testserver.NewPKCE(t)
		resp := web.Authorize(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, nil))
		id := testserver.Location(t, resp).Query().Get("authRequest")
		resp, _ = web.PostForm(t, "/login", url.Values{"email": {"norole@example.com"}, "password": {userPass2}, "authRequest": {id}})
		resp, _ = web.Get(t, resp.Header.Get("Location"))
		redirectError(t, resp, "invalid_scope")
	})

	// I16: the discovery document.
	t.Run("I16_discovery", func(t *testing.T) {
		_, b := f.a.Get(t, "/.well-known/openid-configuration")
		m := decode(t, b)
		if !slices.Equal(toStrings(m["grant_types_supported"]), []string{"client_credentials", "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"}) ||
			!slices.Equal(toStrings(m["scopes_supported"]), []string{"openid", "profile", "email", "offline_access"}) ||
			!slices.Equal(toStrings(m["token_endpoint_auth_methods_supported"]), []string{"private_key_jwt", "none"}) {
			t.Fatalf("discovery = %v", m)
		}
	})

	// I28: a restart with a clients file without the client.
	t.Run("I28_restart_clients_file", func(t *testing.T) {
		tr, _ := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		cfgDB := f.a.DB
		f.a.Stop()
		a2 := h.start(t, testserver.WithDB(cfgDB), testserver.WithPublicClients(t, []testserver.PublicClient{adminUI}))
		web := a2.NewWeb()
		resp := web.Authorize(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, testserver.NewPKCE(t), nil))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize after the client left the file: %d", resp.StatusCode)
		}
		_, r := a2.TokenRequest(t, testserver.RefreshForm("demo-ui", tr.RefreshToken))
		if r.Error != "invalid_grant" {
			t.Fatalf("refresh after the client left the file: %+v", r)
		}
	})
	_ = pages.CookieName
}

// codeIDToken does a code flow and returns the ID token.
func (f *fixture) codeIDToken(email, scope string) string {
	f.t.Helper()
	tr, _ := f.login(email, userPass2, "demo-ui", demoRedirect, scope)
	return tr.IDToken
}
