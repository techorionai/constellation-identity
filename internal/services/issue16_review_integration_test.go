//go:build integration

package services_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/resources/test/oidcprovider"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

// TestIssue16ReviewIntegration has the exploits of the security findings R1, R2,
// and R3 of the review of the PR. Each exploit must fail.
func TestIssue16ReviewIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	p := oidcprovider.Start(t)
	f := newFixture(t, h, mfaOptions(testserver.WithIdp(testserver.IdpSettings{Provider: p, Google: true, Microsoft: true}))...)
	r := newIdpRig(f, p)
	const demoRole = "demo:agent"

	// R3: a holder of a young stolen session cannot start a link with no proof of a
	// local factor, and a wrong password gives no proof.
	t.Run("R3_link_needs_the_local_factor", func(t *testing.T) {
		id, web := f.userWithPassword("r3a@example.com", demoRole)
		before := len(p.AuthRequests())
		p.Expect(google("g-r3-attacker", "attacker@example.com"))
		resp, _ := web.Get(t, "/login/oidc/google?purpose=link")
		status(t, resp, http.StatusSeeOther, "start with no proof")
		if loc := resp.Header.Get("Location"); loc != "/account/identity-links/google/link" {
			t.Fatalf("Location = %q", loc)
		}
		resp, body := web.PostForm(t, "/account/identity-links/google/link", url.Values{"password": {"wrong password long"}})
		status(t, resp, http.StatusUnauthorized, "wrong password")
		if !strings.Contains(string(body), "The password or the code is not right.") {
			t.Fatalf("body = %s", body)
		}
		// A value that the attacker makes up is no proof.
		resp, _ = web.Get(t, "/login/oidc/google?purpose=link&confirm=made-up-value")
		status(t, resp, http.StatusSeeOther, "start with a made up proof")
		if len(p.AuthRequests()) != before || f.linkCount(id) != 0 {
			t.Fatal("the service must send no request to the provider and add no link")
		}
		// The proof of the right password works one time.
		path := r.confirmLink(web, "google", userPassword)
		resp, body = r.run(web, path, google("g-r3", "r3a@example.com"))
		if resp.StatusCode != http.StatusSeeOther || f.linkCount(id) != 1 {
			t.Fatalf("link with the proof: %d %s", resp.StatusCode, body)
		}
		resp, _ = web.Get(t, path)
		status(t, resp, http.StatusSeeOther, "second use of the proof")
		if loc := resp.Header.Get("Location"); loc != "/account/identity-links/google/link" {
			t.Fatalf("Location after the second use = %q", loc)
		}
	})

	// R3: a user with no local factor needs an ID token with a valid auth_time. A
	// token with no auth_time is refused, also if the iat is new.
	t.Run("R3_no_factor_needs_auth_time", func(t *testing.T) {
		tok := f.adminToken(adminScopes)
		id, itoken := f.inviteUser(tok, "r3b@example.com", demoRole)
		web := f.a.NewWeb()
		resp, _ := r.run(web, "/login/oidc/google?purpose=invite&token="+itoken, google("g-r3b", "r3b@example.com"))
		status(t, resp, http.StatusSeeOther, "invite")
		path := r.confirmLink(web, "microsoft", "")
		// The provider does not make the user log in again, so the token has no auth_time.
		ms := microsoft("oid-r3b", "r3b@example.com")
		ms.NoUserStep = true
		resp, body := r.run(web, path, ms)
		status(t, resp, http.StatusBadRequest, "token with no auth_time")
		if !strings.Contains(string(body), "The login did not complete.") || f.linkCount(id) != 1 {
			t.Fatalf("body = %s, links = %d", body, f.linkCount(id))
		}
		// A token with an old auth_time is refused too.
		ms.AuthTime = f.clock.Now().Add(-10 * time.Minute)
		resp, _ = r.run(web, path, ms)
		status(t, resp, http.StatusBadRequest, "token with an old auth_time")
		if f.linkCount(id) != 1 {
			t.Fatal("no link")
		}
		// The provider asks the user to log in again, so the token has a new auth_time.
		resp, body = r.run(web, path, microsoft("oid-r3b", "r3b@example.com"))
		if resp.StatusCode != http.StatusSeeOther || f.linkCount(id) != 2 {
			t.Fatalf("link with an auth_time: %d %s", resp.StatusCode, body)
		}
	})

	// R3: the removal of a link needs the password or a code on the page. A stolen
	// young session has no password. A user with no local factor cannot remove.
	t.Run("R3_removal_needs_the_local_factor", func(t *testing.T) {
		id, web := f.userWithPassword("r3c@example.com", demoRole)
		r.link(web, "google", google("g-r3c", "r3c@example.com"))
		resp, body := web.PostForm(t, "/account/identity-links/google/remove", url.Values{})
		status(t, resp, http.StatusUnauthorized, "removal with no password")
		if !strings.Contains(string(body), "The password or the code is not right.") || f.linkCount(id) != 1 {
			t.Fatalf("body = %s", body)
		}
		resp, _ = web.PostForm(t, "/account/identity-links/google/remove", url.Values{"password": {"wrong password long"}})
		status(t, resp, http.StatusUnauthorized, "removal with a wrong password")
		if f.linkCount(id) != 1 {
			t.Fatal("the link must stay")
		}
		// The API call with a token of an upstream login shows no local factor.
		fed := r.fedTokens(f.a.NewWeb(), "google", google("g-r3c", "r3c@example.com"), linkScope)
		resp2, m := f.api(fed.AccessToken, http.MethodDelete, "/v1/me/identity-links/google", nil)
		if resp2.StatusCode != http.StatusUnauthorized || code(m) != "reauthentication_required" || f.linkCount(id) != 1 {
			t.Fatalf("API removal with a fed token: %d %v", resp2.StatusCode, m)
		}
		resp, _ = web.PostForm(t, "/account/identity-links/google/remove", url.Values{"password": {userPassword}})
		status(t, resp, http.StatusSeeOther, "removal with the password")
		if f.linkCount(id) != 0 {
			t.Fatal("the link must be gone")
		}
	})

	// R1: the first password writes the audit entry and sends the notice.
	t.Run("R1_set_password_audit", func(t *testing.T) {
		tok := f.adminToken(adminScopes)
		id, itoken := f.inviteUser(tok, "r1@example.com", demoRole)
		web := f.a.NewWeb()
		resp, _ := r.run(web, "/login/oidc/google?purpose=invite&token="+itoken, google("g-r1", "r1@example.com"))
		status(t, resp, http.StatusSeeOther, "invite")
		auditsBefore, noticesBefore := len(auditsOf(t, f.a, "identity:password:set")), len(noticesOf(t, f.a, "password_set"))
		f.a.ledger.add(&f.a.ledger.passwords, userPassword)
		resp, _ = web.PostForm(t, "/account/password", url.Values{"password": {userPassword}, "password2": {userPassword}})
		status(t, resp, http.StatusSeeOther, "set the password")
		audits := auditsOf(t, f.a, "identity:password:set")
		if len(audits) != auditsBefore+1 || len(noticesOf(t, f.a, "password_set")) != noticesBefore+1 {
			t.Fatalf("audit entries %d, notices %d", len(audits), len(noticesOf(t, f.a, "password_set")))
		}
		last := audits[len(audits)-1]
		if last["target_user_id"] != id && last["target"] != id && last["actor"] != id {
			t.Fatalf("the audit entry does not name the user: %v", last)
		}
		// A second call does not write a second entry.
		resp, _ = web.PostForm(t, "/account/password", url.Values{"password": {userPassword}, "password2": {userPassword}})
		status(t, resp, http.StatusSeeOther, "second call")
		if len(auditsOf(t, f.a, "identity:password:set")) != auditsBefore+1 {
			t.Fatal("a second call writes no entry")
		}
	})

	// R2: a pending login with the method fed ends when the link is removed.
	t.Run("R2_pending_login_ends_with_the_link", func(t *testing.T) {
		u := f.newTOTPUser("r2@example.com", demoRole)
		r.link(u.web, "google", google("g-r2", "r2@example.com"))
		// The attacker controls the Google account and knows a code. The login goes to the page of the second factor.
		attacker := f.a.NewWeb()
		r.loginToMFA(attacker, google("g-r2", "r2@example.com"))
		// The user removes the link.
		resp, _ := u.web.PostForm(t, "/account/identity-links/google/remove", url.Values{"password": {userPassword}})
		status(t, resp, http.StatusSeeOther, "removal")
		if f.linkCount(u.id) != 0 {
			t.Fatal("the link must be gone")
		}
		// The attacker sends the code. The service makes no session.
		f.advance(31 * time.Second)
		resp, _ = attacker.PostForm(t, "/login/mfa", url.Values{"code": {testserver.TOTPCode(t, u.secret, f.clock.Now())}})
		if attacker.Cookie(pages.CookieName) != "" {
			t.Fatalf("the attacker got a session: %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusSeeOther && !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
			t.Fatalf("Location = %q", resp.Header.Get("Location"))
		}
	})
}
