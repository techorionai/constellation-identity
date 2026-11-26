//go:build integration

package services_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/internal/services"
	"github.com/techorionai/constellation-identity/resources/test/oidcprovider"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
	swa "github.com/techorionai/constellation-identity/resources/test/webauthn"
)

// loginToMFA does the upstream login of a user with a local second factor, up to
// the page of the second factor. It returns the auth request ID and the PKCE
// values of the code flow.
func (r *idpRig) loginToMFA(web *testserver.Web, l oidcprovider.Login) (string, testserver.PKCE) {
	r.f.t.Helper()
	id, pk := r.beginAuthorize(web, mfaScope)
	resp, body := r.run(web, "/login/oidc/google?purpose=login&authRequest="+id, l)
	status(r.f.t, resp, http.StatusSeeOther, "upstream login with a second factor")
	if resp.Header.Get("Location") != "/login/mfa" {
		r.f.t.Fatalf("Location = %q: %s", resp.Header.Get("Location"), body)
	}
	if web.Cookie(pages.MFACookieName) == "" || web.Cookie(pages.CookieName) != "" {
		r.f.t.Fatal("the pending login needs the cookie of the pending login and no session")
	}
	r.f.a.ledger.add(&r.f.a.ledger.flow, web.Cookie(pages.MFACookieName))
	return id, pk
}

// I6, I32: the local second factor after an upstream login.
func TestIssue16SecondFactorIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	p := oidcprovider.Start(t)
	f := newFixture(t, h, mfaOptions(testserver.WithIdp(testserver.IdpSettings{Provider: p, Google: true}))...)
	r := newIdpRig(f, p)
	const demoRole = "demo:agent"

	t.Run("I6_totp_and_recovery", func(t *testing.T) {
		u := f.newTOTPUser("i6@example.com", demoRole)
		r.link(u.web, "google", google("g-i6", "i6@example.com"))
		web := f.a.NewWeb()
		_, pk := r.loginToMFA(web, google("g-i6", "i6@example.com"))
		page := f.page(web, "/login/mfa")
		if !strings.Contains(page, "You logged in with your upstream account.") || !strings.Contains(page, `name="code"`) {
			t.Fatalf("the page of the second factor: %s", page)
		}
		f.advance(31 * time.Second)
		loc := f.finishMFALogin(web, testserver.TOTPCode(t, u.secret, f.clock.Now()), false)
		tr := f.exchangeCode(loc, pk, "admin-ui", adminRedirect)
		if got := amrOf(t, tr.AccessToken); got != "fed otp mfa" {
			t.Fatalf("amr = %q", got)
		}
		// A recovery code.
		web2 := f.a.NewWeb()
		_, pk2 := r.loginToMFA(web2, google("g-i6", "i6@example.com"))
		loc = f.finishMFALogin(web2, u.codes[0], true)
		tr = f.exchangeCode(loc, pk2, "admin-ui", adminRedirect)
		if got := amrOf(t, tr.AccessToken); got != "fed rec mfa" {
			t.Fatalf("amr = %q", got)
		}
		// A wrong code gives no session.
		web3 := f.a.NewWeb()
		r.loginToMFA(web3, google("g-i6", "i6@example.com"))
		resp, _ := web3.PostForm(t, "/login/mfa", url.Values{"code": {"000000"}})
		status(t, resp, http.StatusUnauthorized, "wrong code")
		if web3.Cookie(pages.CookieName) != "" {
			t.Fatal("no session after a wrong code")
		}
	})

	t.Run("I32_passkey", func(t *testing.T) {
		u := f.newPasskeyUser("i32@example.com", swa.ES256, demoRole)
		r.link(u.web, "google", google("g-i32", "i32@example.com"))
		for _, c := range []struct {
			uv   bool
			want string
		}{{true, "fed hwk user mfa"}, {false, "fed hwk mfa"}} {
			web := f.a.NewWeb()
			_, pk := r.loginToMFA(web, google("g-i32", "i32@example.com"))
			resp, _, raw := f.jsonPost(web, "/login/mfa/passkey/options", []byte(`{}`))
			status(t, resp, http.StatusOK, "second factor options")
			response := u.key.Get(t, raw, swa.WithUV(c.uv))
			f.trackWebAuthn(raw, u.key)
			resp, m, _ := f.jsonPost(web, "/login/mfa/passkey/finish", response)
			status(t, resp, http.StatusOK, "second factor finish")
			next, _ := m["redirect"].(string)
			f.a.trackSession(web)
			resp, _ = web.Get(t, next)
			status(t, resp, http.StatusFound, "continue")
			tr := f.exchangeCode(testserver.Location(t, resp), pk, "admin-ui", adminRedirect)
			if got := amrOf(t, tr.AccessToken); got != c.want {
				t.Fatalf("amr = %q, want %q", got, c.want)
			}
			if got := f.amrOfSession(web); got != c.want {
				t.Fatalf("session methods = %q, want %q", got, c.want)
			}
		}
	})

	t.Run("I32_totp_setup_in_a_fed_session", func(t *testing.T) {
		_, web := f.userWithPassword("i32c@example.com", demoRole)
		r.link(web, "google", google("g-i32c", "i32c@example.com"))
		fedWeb := f.a.NewWeb()
		r.fedTokens(fedWeb, "google", google("g-i32c", "i32c@example.com"), mfaScope)
		if got := f.amrOfSession(fedWeb); got != "fed" {
			t.Fatalf("methods before = %q", got)
		}
		f.setupTOTP(fedWeb)
		if got := f.amrOfSession(fedWeb); got != "fed otp mfa" {
			t.Fatalf("methods after the setup = %q", got)
		}
	})
}

// I14, I16, I17, I28, I29, I30, I40: the admin side, with the rule "MFA for admins".
func TestIssue16AdminIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	p := oidcprovider.Start(t)
	f := newFixture(t, h, mfaOptions(requireAdmins(), testserver.WithIdp(testserver.IdpSettings{Provider: p, Google: true}))...)
	r := newIdpRig(f, p)
	const demoRole = "demo:agent"
	admin := f.newMFAAdmin()
	adminTok := func(scope string) string {
		f.t.Helper()
		return f.mfaToken(admin, "admin-ui", adminRedirect, scope, nil).AccessToken
	}
	manage := adminTok(adminLinkScp + " identity:api_token:manage_own")

	// I14: an admin with an upstream login and no local factor must set up MFA.
	t.Run("I14_admin_needs_mfa", func(t *testing.T) {
		_, itoken := f.inviteUser(manage, "i14@example.com", "identity:admin")
		web := f.a.NewWeb()
		resp, body := r.run(web, "/login/oidc/google?purpose=invite&token="+itoken, google("g-i14", "i14@example.com"))
		status(t, resp, http.StatusSeeOther, "invite")
		if resp.Header.Get("Location") != "/account/totp?required=1" {
			t.Fatalf("Location = %q: %s", resp.Header.Get("Location"), body)
		}
		w2 := f.a.NewWeb()
		id, _ := r.beginAuthorize(w2, mfaScope)
		resp, _ = r.run(w2, "/login/oidc/google?purpose=login&authRequest="+id, google("g-i14", "i14@example.com"))
		status(t, resp, http.StatusSeeOther, "login")
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/account/totp?required=1&authRequest=") {
			t.Fatalf("Location = %q", loc)
		}
	})

	// I16, I27, I28, I38, I40: the admin operations of the links.
	t.Run("I16_admin_operations", func(t *testing.T) {
		email := "i16@example.com"
		id := f.newUser(manage, email, userPassword, demoRole)
		web := f.a.NewWeb()
		f.passwordLogin(web, email, userPassword, "/login/done")
		r.link(web, "google", google("g-i16", email))
		// The user logs in with Google in a second browser and makes an API token.
		attacker := f.a.NewWeb()
		fed := r.fedTokens(attacker, "google", google("g-i16", email), linkScope)
		resp, m := f.api(fed.AccessToken, http.MethodPost, "/v1/me/api-tokens", map[string]any{"name": "fed token", "scope": "demo:ticket:read"})
		status(t, resp, http.StatusCreated, "API token of the fed session")
		f.a.ledger.add(&f.a.ledger.apiTokens, testserver.APITokenOf(t, m))
		// A token from before the migration has an empty amr.
		if _, err := f.a.Pool(t).Exec(ctx, `INSERT INTO api_tokens (id, token_hash, user_id, name, scope, created_at, expires_at)
			VALUES ('00000000-0000-4000-8000-0000000000f9', 'old-hash', $1, 'old token', 'demo:ticket:read', now(), now() + interval '30 days')`, id); err != nil {
			t.Fatal(err)
		}

		// The list needs identity:identity_link:read. identity:user:read is not enough.
		list := "/v1/users/" + id + "/identity-links"
		userRead := adminTok("openid identity:user:read")
		if resp, m := f.api(userRead, http.MethodGet, list, nil); resp.StatusCode != http.StatusForbidden || code(m) != "insufficient_scope" {
			t.Fatalf("list with user:read: %d %v", resp.StatusCode, m)
		}
		resp, m = f.api(manage, http.MethodGet, list, nil)
		status(t, resp, http.StatusOK, "UserIdentityLinks_list")
		items, _ := m["items"].([]any)
		if len(items) != 1 || items[0].(map[string]any)["provider"] != "google" {
			t.Fatalf("list = %v", m)
		}
		if resp, m := f.api(manage, http.MethodGet, "/v1/users/00000000-0000-4000-8000-0000000000fa/identity-links", nil); resp.StatusCode != http.StatusNotFound || code(m) != "user_not_found" {
			t.Fatalf("unknown user: %d %v", resp.StatusCode, m)
		}
		// The removal needs the key, identity:admin, and a fresh MFA login.
		rm := list + "/google"
		writeOnly := adminTok("openid identity:user:write")
		if resp, m := f.api(writeOnly, http.MethodDelete, rm, nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("remove with user:write: %d %v", resp.StatusCode, m)
		}
		for _, bad := range []string{"/v1/users/" + id + "/identity-links/okta", "/v1/users/" + id + "/identity-links/Google", "/v1/users/" + id + "/identity-links/microsoft"} {
			if resp, m := f.api(manage, http.MethodDelete, bad, nil); resp.StatusCode != http.StatusNotFound || code(m) != "identity_link_not_found" {
				t.Fatalf("%s: %d %v", bad, resp.StatusCode, m)
			}
		}
		if resp, m := f.api(manage, http.MethodDelete, "/v1/users/not-a-uuid/identity-links/google", nil); resp.StatusCode != http.StatusNotFound || code(m) != "user_not_found" {
			t.Fatalf("bad user ID: %d %v", resp.StatusCode, m)
		}
		// I26: a stale token gets the MFA challenge, and the link stays.
		f.advance(6 * time.Minute)
		resp, m = f.api(manage, http.MethodDelete, rm, nil)
		if resp.StatusCode != http.StatusUnauthorized || code(m) != "reauthentication_required" ||
			!strings.Contains(resp.Header.Get("WWW-Authenticate"), "A fresh MFA login is necessary") || f.linkCount(id) != 1 {
			t.Fatalf("stale token: %d %v %q", resp.StatusCode, m, resp.Header.Get("WWW-Authenticate"))
		}
		fresh := adminTok(adminLinkScp)
		resp, m = f.api(fresh, http.MethodDelete, rm, nil)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove: %d %v", resp.StatusCode, m)
		}
		// I27 and I38: the session of the attacker, and the token of the fed session, end.
		if resp, _ := attacker.Get(t, "/account/security"); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("the fed session must end: %d", resp.StatusCode)
		}
		if resp, _ := web.Get(t, "/account/security"); resp.StatusCode != http.StatusOK {
			t.Fatalf("the password session must stay: %d", resp.StatusCode)
		}
		if f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND name = 'fed token' AND revoked_at IS NOT NULL`, id) != 1 {
			t.Fatal("the token of the fed session must end")
		}
		// I40: a token from before the migration has an empty amr and stays valid.
		if f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND name = 'old token' AND revoked_at IS NULL AND amr = '{}'`, id) != 1 {
			t.Fatal("an old token stays valid")
		}
		// I28: the audit entry has the admin as actor.
		var found bool
		for _, rec := range recordsOf(t, f.a, "identity.audit") {
			if rec["action"] == "identity:identity_link:remove" && rec["actor"] == admin.id && rec["target_user_id"] == id {
				found = true
			}
		}
		if !found || len(noticesOf(t, f.a, "identity_link_removed")) == 0 {
			t.Fatal("no audit entry or notice for the removal by the admin")
		}
		// The list is empty now, and the removal again gives 404.
		resp, m = f.api(fresh, http.MethodDelete, rm, nil)
		if resp.StatusCode != http.StatusNotFound || code(m) != "identity_link_not_found" {
			t.Fatalf("second removal: %d %v", resp.StatusCode, m)
		}
	})

	// I40: the API token records the amr of the session that made it.
	t.Run("I40_token_amr", func(t *testing.T) {
		if resp, m := f.api(manage, http.MethodPut, "/v1/users/"+admin.id+"/roles/"+demoRole, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("assign: %d %v", resp.StatusCode, m)
		}
		resp, m := f.api(manage, http.MethodPost, "/v1/me/api-tokens", map[string]any{"name": "admin token", "scope": "demo:ticket:read"})
		status(t, resp, http.StatusCreated, "MeApiTokens_create")
		f.a.ledger.add(&f.a.ledger.apiTokens, testserver.APITokenOf(t, m))
		if f.countWhere(`SELECT count(*) FROM api_tokens WHERE name = 'admin token' AND amr = ARRAY['pwd','otp','mfa']`) != 1 {
			t.Fatal("the token records the amr of the session")
		}
		if _, has := m["amr"]; has {
			t.Fatal("the response shows the amr")
		}
	})

	// I29, I30: a user with no password and a passkey only. The reset of the MFA
	// is refused. The subcommand has a way around the rule.
	t.Run("I29_I30_reset", func(t *testing.T) {
		const email = "i29@example.com"
		id, itoken := f.inviteUser(manage, email, demoRole)
		web := f.a.NewWeb()
		resp, _ := r.run(web, "/login/oidc/google?purpose=invite&token="+itoken, google("g-i29", email))
		status(t, resp, http.StatusSeeOther, "invite")
		key := f.newAuthenticator(swa.ES256)
		if resp, m := f.registerPasskey(web, key, "Only"); resp.StatusCode != http.StatusOK {
			t.Fatalf("register: %d %v", resp.StatusCode, m)
		}
		if _, err := f.a.Pool(t).Exec(ctx, `DELETE FROM identity_links WHERE user_id = $1`, id); err != nil {
			t.Fatal(err)
		}
		reset := "/v1/users/" + id + "/mfa"
		resp2, m := f.api(adminTok(adminLinkScp), http.MethodDelete, reset, nil)
		if resp2.StatusCode != http.StatusConflict || code(m) != "last_login_method" {
			t.Fatalf("reset: %d %v", resp2.StatusCode, m)
		}
		if f.passkeyRows(id) != 1 || f.countWhere(`SELECT count(*) FROM users WHERE id = $1 AND status = 'active'`, id) != 1 {
			t.Fatal("a refused reset changes nothing")
		}
		// I30: the subcommand.
		if err := services.ResetMFA(ctx, f.a.Config, email, f.a.logs.Logger()); err != nil {
			t.Fatal(err)
		}
		if f.passkeyRows(id) != 0 || f.countWhere(`SELECT count(*) FROM users WHERE id = $1 AND status = 'active'`, id) != 1 {
			t.Fatal("the subcommand removes the passkeys and keeps the status")
		}
		var logged bool
		for _, rec := range f.a.logs.Records(t) {
			if rec["event"] == "identity.mfa.reset_last_login_method" {
				logged = true
			}
		}
		if !logged {
			t.Fatal("no log event identity.mfa.reset_last_login_method")
		}
	})
}

// I25: the warning at the start for users with no login method.
func TestIssue16StartupWarningIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	p := oidcprovider.Start(t)
	idp := testserver.WithIdp(testserver.IdpSettings{Provider: p, Google: true})
	f := newFixture(t, h, mfaOptions(idp)...)
	r := newIdpRig(f, p)
	_, itoken := f.inviteUser(f.adminToken(adminScopes), "i25@example.com", "demo:agent")
	resp, _ := r.run(f.a.NewWeb(), "/login/oidc/google?purpose=invite&token="+itoken, google("g-i25", "i25@example.com"))
	status(t, resp, http.StatusSeeOther, "invite")
	f.a.Stop()
	warnings := func(a *app) []map[string]any {
		var out []map[string]any
		for _, rec := range a.logs.Records(t) {
			if rec["event"] == "identity.idp.users_without_login_method" {
				out = append(out, rec)
			}
		}
		return out
	}
	// The provider is off: the user has no login method.
	off := h.start(t, testserver.WithDB(f.a.DB))
	w := warnings(off)
	if len(w) != 1 || w[0]["count"] != float64(1) {
		t.Fatalf("warnings with the provider off = %v", w)
	}
	off.Stop()
	// The provider is on: no warning.
	on := h.start(t, testserver.WithDB(f.a.DB), idp)
	if w := warnings(on); len(w) != 0 {
		t.Fatalf("warnings with the provider on = %v", w)
	}
}
