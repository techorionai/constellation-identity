//go:build integration

package services_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/resources/test/oidcprovider"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
	swa "github.com/techorionai/constellation-identity/resources/test/webauthn"
)

// TestIssue16R3Integration has the exploits and the good flows of the decision
// P23 for the passkey and for the removal of a user with no local factor.
func TestIssue16R3Integration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	p := oidcprovider.Start(t)
	f := newFixture(t, h, mfaOptions(testserver.WithIdp(testserver.IdpSettings{Provider: p, Google: true, Microsoft: true}))...)
	r := newIdpRig(f, p)
	const demoRole = "demo:agent"

	// inviteFed makes a user with a Google link, no password, and no second
	// factor. The browser has a fresh session of the invite.
	inviteFed := func(email, sub string) (string, *testserver.Web) {
		t.Helper()
		id, itoken := f.inviteUser(f.adminToken(adminScopes), email, demoRole)
		web := f.a.NewWeb()
		resp, _ := r.run(web, "/login/oidc/google?purpose=invite&token="+itoken, google(sub, email))
		status(t, resp, http.StatusSeeOther, "invite")
		return id, web
	}
	// linkNoFactor links a Microsoft account of a user with no local factor. The
	// provider sends a new auth_time, so the link passes the rule of P23.
	linkNoFactor := func(web *testserver.Web, id, oid, email string) {
		t.Helper()
		path := r.confirmLink(web, "microsoft", "")
		resp, body := r.run(web, path, microsoft(oid, email))
		if resp.StatusCode != http.StatusSeeOther || f.linkCount(id) != 2 {
			t.Fatalf("link: %d %s", resp.StatusCode, body)
		}
	}
	// passkeyCheck does the passkey check of a link or a link removal on the
	// page. It returns the answer of the finish step.
	passkeyCheck := func(web *testserver.Web, key *swa.Authenticator, finish string) (testserver.Response, map[string]any) {
		t.Helper()
		resp, _, raw := f.jsonPost(web, "/account/identity-links/passkey/options", []byte(`{}`))
		status(t, resp, http.StatusOK, "passkey check options")
		response := key.Get(t, raw)
		f.trackWebAuthn(raw, key)
		resp, m, _ := f.jsonPost(web, finish, response)
		return resp, m
	}

	// A passkey is a local factor for a link. A user with only a passkey and a
	// Google link can link a Microsoft account and can remove a link.
	t.Run("passkey_links_and_removes", func(t *testing.T) {
		id, web := inviteFed("r3p@example.com", "g-r3p")
		key := f.newAuthenticator(swa.ES256)
		resp, m := f.registerPasskey(web, key, "First")
		status(t, resp, http.StatusOK, "register the passkey")
		_ = m

		// The exploit: the start with no proof does not reach the provider.
		before := len(p.AuthRequests())
		resp, _ = web.Get(t, "/login/oidc/microsoft?purpose=link")
		status(t, resp, http.StatusSeeOther, "start with no proof")
		if len(p.AuthRequests()) != before {
			t.Fatal("no request to the provider without the proof")
		}
		page := f.page(web, "/account/identity-links/microsoft/link")
		if !strings.Contains(page, `data-passkey="link-confirm"`) {
			t.Fatalf("the page has no passkey check: %s", page)
		}
		// The exploit: a response with no ceremony, and a response of a key that the
		// user does not have, give no proof.
		resp, m, _ = f.jsonPost(web, "/account/identity-links/passkey/link?provider=microsoft", []byte(`{}`))
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("response with no ceremony: %d %v", resp.StatusCode, m)
		}
		resp, _, raw := f.jsonPost(web, "/account/identity-links/passkey/options", []byte(`{}`))
		status(t, resp, http.StatusOK, "options")
		// The key belongs to another user.
		_, otherWeb := f.userWithPassword("r3p-other@example.com", demoRole)
		other := f.newAuthenticator(swa.ES256)
		resp2, _ := f.registerPasskey(otherWeb, other, "Other")
		status(t, resp2, http.StatusOK, "register the key of another user")
		resp, m, _ = f.jsonPost(web, "/account/identity-links/passkey/link?provider=microsoft", other.Get(t, raw, swa.WithCredential(other.Creds[0])))
		status(t, resp, http.StatusUnauthorized, "response of an unknown key")
		if m["error"] != "invalid_passkey" || f.linkCount(id) != 1 {
			t.Fatalf("answer = %v", m)
		}
		// The good check gives the address of the start, with the proof.
		resp, m = passkeyCheck(web, key, "/account/identity-links/passkey/link?provider=microsoft")
		status(t, resp, http.StatusOK, "passkey check for the link")
		next, _ := m["redirect"].(string)
		if !strings.HasPrefix(next, "/login/oidc/microsoft?purpose=link&confirm=") {
			t.Fatalf("redirect = %q", next)
		}
		f.a.ledger.add(&f.a.ledger.flow, strings.TrimPrefix(next, "/login/oidc/microsoft?purpose=link&confirm="))
		resp, body := r.run(web, next, microsoft("oid-r3p", "r3p@example.com"))
		if resp.StatusCode != http.StatusSeeOther || f.linkCount(id) != 2 {
			t.Fatalf("link with the passkey: %d %s", resp.StatusCode, body)
		}

		// The removal. The password form gives nothing to a passkey only user.
		resp, _ = web.PostForm(t, "/account/identity-links/microsoft/remove", url.Values{})
		if resp.StatusCode != http.StatusConflict || f.linkCount(id) != 2 {
			t.Fatalf("removal with no proof: %d", resp.StatusCode)
		}
		// The exploit: the finish step of the removal with no ceremony.
		resp, _, _ = f.jsonPost(web, "/account/identity-links/passkey/remove?provider=microsoft", []byte(`{}`))
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest || f.linkCount(id) != 2 {
			t.Fatalf("removal with no ceremony: %d", resp.StatusCode)
		}
		if page := f.page(web, "/account/security"); !strings.Contains(page, `data-passkey="link-remove"`) {
			t.Fatalf("the account page has no passkey removal: %s", page)
		}
		resp, m = passkeyCheck(web, key, "/account/identity-links/passkey/remove?provider=microsoft")
		status(t, resp, http.StatusOK, "removal with the passkey")
		if m["redirect"] != "/login?removed=1" || f.linkCount(id) != 1 {
			t.Fatalf("answer = %v, links = %d", m, f.linkCount(id))
		}
	})

	// A user with no local factor removes a link after an upstream login with a
	// valid auth_time, with an account of the user.
	t.Run("no_factor_removes_with_auth_time", func(t *testing.T) {
		id, web := inviteFed("r3u@example.com", "g-r3u")
		linkNoFactor(web, id, "oid-r3u", "r3u@example.com")
		page := f.page(web, "/account/security")
		if !strings.Contains(page, "/login/oidc/microsoft?purpose=unlink&amp;remove=google") {
			t.Fatalf("the account page has no removal flow: %s", page)
		}
		// The exploit: the form of the password gives nothing.
		resp, _ := web.PostForm(t, "/account/identity-links/google/remove", url.Values{"password": {userPassword}})
		if resp.StatusCode != http.StatusConflict || f.linkCount(id) != 2 {
			t.Fatalf("form removal: %d", resp.StatusCode)
		}
		// The exploit: Google sends no auth_time, so the flow is refused.
		resp, body := r.run(web, "/login/oidc/google?purpose=unlink&remove=microsoft", google("g-r3u", "r3u@example.com"))
		status(t, resp, http.StatusBadRequest, "Google with no auth_time")
		if !strings.Contains(string(body), "The login did not complete.") || f.linkCount(id) != 2 {
			t.Fatalf("body = %s", body)
		}
		// The exploit: a token without a new auth_time is refused.
		old := microsoft("oid-r3u", "r3u@example.com")
		old.NoUserStep = true
		resp, _ = r.run(web, "/login/oidc/microsoft?purpose=unlink&remove=google", old)
		status(t, resp, http.StatusBadRequest, "Microsoft with no auth_time")
		if f.linkCount(id) != 2 {
			t.Fatal("the link must stay")
		}
		// The exploit: a holder of a young session logs in with an own account that
		// has a new auth_time. The account is not a link of the user.
		resp, _ = r.run(web, "/login/oidc/microsoft?purpose=unlink&remove=google", microsoft("oid-attacker", "attacker@example.com"))
		status(t, resp, http.StatusBadRequest, "account of the attacker")
		if f.linkCount(id) != 2 {
			t.Fatal("the link must stay")
		}
		// The good flow: the account of the user, with a new auth_time.
		resp, body = r.run(web, "/login/oidc/microsoft?purpose=unlink&remove=google", microsoft("oid-r3u", "r3u@example.com"))
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login?removed=1" || f.linkCount(id) != 1 {
			t.Fatalf("good flow: %d %q %s", resp.StatusCode, resp.Header.Get("Location"), body)
		}
		// The last link stays. A second removal gives no result.
		resp, _ = r.run(f.a.NewWeb(), "/login/oidc/microsoft?purpose=unlink&remove=microsoft", microsoft("oid-r3u", "r3u@example.com"))
		if f.linkCount(id) != 1 {
			t.Fatalf("a request with no session must not remove: %d", resp.StatusCode)
		}
	})

	// The API call of a user with no local factor needs a token of an upstream
	// login with a valid auth_time. A token of Google, with no auth_time, fails.
	t.Run("no_factor_removes_with_api", func(t *testing.T) {
		id, web := inviteFed("r3a2@example.com", "g-r3a2")
		linkNoFactor(web, id, "oid-r3a2", "r3a2@example.com")
		gTok := r.fedTokens(f.a.NewWeb(), "google", google("g-r3a2", "r3a2@example.com"), linkScope)
		resp, m := f.api(gTok.AccessToken, http.MethodDelete, "/v1/me/identity-links/microsoft", nil)
		if resp.StatusCode != http.StatusUnauthorized || code(m) != "reauthentication_required" || f.linkCount(id) != 2 {
			t.Fatalf("API removal with a token with no auth_time: %d %v", resp.StatusCode, m)
		}
		// The client asks for a new login, so Microsoft sends a new auth_time.
		ms := microsoft("oid-r3a2", "r3a2@example.com")
		ms.AuthTime = f.clock.Now()
		mTok := r.fedTokens(f.a.NewWeb(), "microsoft", ms, linkScope+" offline_access")
		// P24: no token has the value of the upstream auth_time. amr is only "fed".
		for name, tok := range map[string]string{"access token": mTok.AccessToken, "ID token": mTok.IDToken} {
			if tok == "" {
				t.Fatalf("no %s", name)
			}
			_, claims := testserver.JWTClaims(t, tok)
			if amr, _ := claims["amr"].([]any); len(amr) != 1 || amr[0] != "fed" {
				t.Fatalf("%s amr = %v", name, claims["amr"])
			}
			raw, _ := json.Marshal(claims)
			if strings.Contains(string(raw), "fed_auth_time") {
				t.Fatalf("%s has fed_auth_time: %s", name, raw)
			}
		}
		// A refreshed access token keeps the proof, because the family keeps the flag.
		_, refreshed := f.a.TokenRequest(t, testserver.RefreshForm("admin-ui", mTok.RefreshToken))
		if refreshed.AccessToken == "" {
			t.Fatalf("refresh: %v", refreshed.Error)
		}
		_, rc := testserver.JWTClaims(t, refreshed.AccessToken)
		if raw, _ := json.Marshal(rc); strings.Contains(string(raw), "fed_auth_time") {
			t.Fatalf("refreshed token has fed_auth_time: %s", raw)
		}
		resp, m = f.api(refreshed.AccessToken, http.MethodDelete, "/v1/me/identity-links/google", nil)
		if resp.StatusCode != http.StatusNoContent || f.linkCount(id) != 1 {
			t.Fatalf("API removal with an auth_time: %d %v", resp.StatusCode, m)
		}
	})

	// A user with a password does not pass the API call with the upstream proof.
	t.Run("password_user_needs_local_factor_in_api", func(t *testing.T) {
		id, web := f.userWithPassword("r3pw@example.com", demoRole)
		r.link(web, "microsoft", microsoft("oid-r3pw", "r3pw@example.com"))
		tok := r.fedTokens(f.a.NewWeb(), "microsoft", microsoft("oid-r3pw", "r3pw@example.com"), linkScope)
		resp, m := f.api(tok.AccessToken, http.MethodDelete, "/v1/me/identity-links/microsoft", nil)
		if resp.StatusCode != http.StatusUnauthorized || f.linkCount(id) != 1 {
			t.Fatalf("API removal with the upstream proof only: %d %v", resp.StatusCode, m)
		}
	})
}
