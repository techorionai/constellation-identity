//go:build integration

package services_test

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/resources/test/oidcprovider"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

const (
	linkScope    = "openid identity:identity_link:manage_own identity:api_token:manage_own identity:mfa:manage_own"
	adminLinkScp = "openid identity:identity_link:read identity:identity_link:remove identity:admin identity:user:read identity:user:write identity:role:read identity:role:assign identity:mfa:reset identity:mfa:read"
)

// idpRig drives the upstream flows of a fixture against the test provider.
type idpRig struct {
	f *fixture
	p *oidcprovider.Provider
}

func newIdpRig(f *fixture, p *oidcprovider.Provider) *idpRig {
	p.Clock = f.clock.Now
	return &idpRig{f: f, p: p}
}

// noRedirect is the client of the steps at the provider.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// start sends the start request of a flow. If the service redirects to the
// provider, it returns the authorization URL.
func (r *idpRig) start(web *testserver.Web, path string) (testserver.Response, []byte, string) {
	r.f.t.Helper()
	resp, body := web.Get(r.f.t, path)
	if resp.StatusCode != http.StatusFound {
		return resp, body, ""
	}
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil || !strings.HasPrefix(loc, r.p.GoogleBase()) && !strings.HasPrefix(loc, r.p.MicrosoftBase()) {
		r.f.t.Fatalf("the start redirects to %q, not to the test provider", loc)
	}
	q := u.Query()
	for _, k := range []string{"state", "nonce"} {
		r.f.a.ledger.add(&r.f.a.ledger.flow, q.Get(k))
	}
	for _, v := range web.CookiesWithPrefix(pages.IdpCookieName) {
		r.f.a.ledger.add(&r.f.a.ledger.flow, v)
	}
	return resp, body, loc
}

// finish visits the provider and then the callback of the service. It returns
// the answer of the callback and the callback URL.
func (r *idpRig) finish(web *testserver.Web, authURL string) (testserver.Response, []byte, *url.URL) {
	r.f.t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		r.f.t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: r.p.Transport(), CheckRedirect: noRedirect.CheckRedirect}).Do(req)
	if err != nil {
		r.f.t.Fatal(err)
	}
	_ = resp.Body.Close()
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		r.f.t.Fatalf("the provider answers %d with Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, k := range []string{"code", "state"} {
		if v := cb.Query().Get(k); v != "" {
			r.f.a.ledger.add(&r.f.a.ledger.flow, v)
		}
	}
	got, body := web.Get(r.f.t, cb.RequestURI())
	return got, body, cb
}

// run does the whole flow with the login that the provider gives.
func (r *idpRig) run(web *testserver.Web, path string, l oidcprovider.Login) (testserver.Response, []byte) {
	r.f.t.Helper()
	r.p.Expect(l)
	resp, body, authURL := r.start(web, path)
	if authURL == "" {
		return resp, body
	}
	resp, body, _ = r.finish(web, authURL)
	return resp, body
}

// google and microsoft make the logins of the test provider.
func google(sub, email string) oidcprovider.Login {
	return oidcprovider.Login{Provider: "google", Sub: sub, Email: email}
}

func microsoft(oid, email string) oidcprovider.Login {
	return oidcprovider.Login{Provider: "microsoft", Oid: oid, Tid: oidcprovider.TenantA, Email: email, XmsEdov: true}
}

// secrets that must not be in a log record or in a span.
func (r *idpRig) track(values ...string) {
	for _, v := range values {
		r.f.a.ledger.add(&r.f.a.ledger.flow, v)
	}
}

// beginAuthorize starts an authorization request of the admin UI and returns the
// auth request ID and the PKCE values.
func (r *idpRig) beginAuthorize(web *testserver.Web, scope string) (string, testserver.PKCE) {
	r.f.t.Helper()
	pk := testserver.NewPKCE(r.f.t)
	resp := web.Authorize(r.f.t, testserver.AuthorizeQuery("admin-ui", adminRedirect, scope, pk, nil))
	loc := testserver.Location(r.f.t, resp)
	id := loc.Query().Get("authRequest")
	if !strings.HasPrefix(loc.Path, "/login") || id == "" {
		r.f.t.Fatalf("authorize: Location = %s", loc)
	}
	r.f.a.ledger.add(&r.f.a.ledger.flow, id)
	return id, pk
}

// fedTokens does the code flow of a user with an upstream login and no second
// factor. It returns the token response.
func (r *idpRig) fedTokens(web *testserver.Web, provider string, l oidcprovider.Login, scope string) testserver.TokenResponse {
	r.f.t.Helper()
	id, pk := r.beginAuthorize(web, scope)
	resp, body := r.run(web, "/login/oidc/"+provider+"?purpose=login&authRequest="+id, l)
	if resp.StatusCode != http.StatusSeeOther {
		r.f.t.Fatalf("callback: %d %s", resp.StatusCode, body)
	}
	next := resp.Header.Get("Location")
	if !strings.HasPrefix(next, "/oauth/authorize/continue?authRequest=") {
		r.f.t.Fatalf("callback: Location = %q", next)
	}
	r.f.a.trackSession(web)
	resp, _ = web.Get(r.f.t, next)
	status(r.f.t, resp, http.StatusFound, "continue")
	return r.f.exchangeCode(testserver.Location(r.f.t, resp), pk, "admin-ui", adminRedirect)
}

// link links an upstream account to the user of a browser with a session. It
// asserts the redirect to the account page.
func (r *idpRig) link(web *testserver.Web, provider string, l oidcprovider.Login) {
	r.f.t.Helper()
	resp, body := r.run(web, r.confirmLink(web, provider, userPassword), l)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account/security" {
		r.f.t.Fatalf("link: %d %q %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
}

// userWithPassword makes a user with a password and a session in a new browser.
func (f *fixture) userWithPassword(email string, roles ...string) (string, *testserver.Web) {
	f.t.Helper()
	id := f.newUser(f.adminToken(adminScopes), email, userPassword, roles...)
	web := f.a.NewWeb()
	f.passwordLogin(web, email, userPassword, "/login/done")
	return id, web
}

// inviteLink makes an invited user with the admin API. It returns the user ID and
// the invite token.
func (f *fixture) inviteUser(adminTok, email string, roles ...string) (string, string) {
	f.t.Helper()
	resp, m := f.api(adminTok, http.MethodPost, "/v1/users", map[string]string{"email": email, "name": "Invited " + email})
	if resp.StatusCode != http.StatusCreated {
		f.t.Fatalf("create user: %d %v", resp.StatusCode, m)
	}
	id := m["user"].(map[string]any)["id"].(string)
	token := testserver.TokenOf(f.t, m["invite"].(map[string]any)["url"].(string))
	f.a.ledger.add(&f.a.ledger.invites, token)
	for _, role := range roles {
		resp, m := f.api(adminTok, http.MethodPut, "/v1/users/"+id+"/roles/"+role, nil)
		if resp.StatusCode != http.StatusOK {
			f.t.Fatalf("assign %s: %d %v", role, resp.StatusCode, m)
		}
	}
	return id, token
}

// linkCount returns the number of links of a user.
func (f *fixture) linkCount(userID string) int {
	f.t.Helper()
	return f.countWhere(`SELECT count(*) FROM identity_links WHERE user_id = $1`, userID)
}

// amrOfSession returns the amr of the session of a browser.
func (f *fixture) amrOfSession(web *testserver.Web) string { return methodsOf(f.t, f, web) }

// page returns a page of a browser and asserts the status 200.
func (f *fixture) page(web *testserver.Web, path string) string {
	f.t.Helper()
	resp, body := web.Get(f.t, path)
	status(f.t, resp, http.StatusOK, "GET "+path)
	return string(body)
}

// continuePattern finds the link of the page that follows the local factor check.
var continuePattern = regexp.MustCompile(`href="(/login/oidc/[^"]+)"`)

// confirmLink does the local factor check of the link page (P23) with the
// password. It returns the path of the start of the flow. A user with no local
// factor gets the path with no confirm value.
func (r *idpRig) confirmLink(web *testserver.Web, provider, password string) string {
	r.f.t.Helper()
	form := url.Values{"password": {password}}
	resp, body := web.PostForm(r.f.t, "/account/identity-links/"+provider+"/link", form)
	m := continuePattern.FindSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil {
		r.f.t.Fatalf("confirm the link: %d %s", resp.StatusCode, body)
	}
	if v := regexp.MustCompile(`confirm=([^&"]+)`).FindSubmatch(m[1]); v != nil {
		r.f.a.ledger.add(&r.f.a.ledger.flow, string(v[1]))
	}
	return html.UnescapeString(string(m[1]))
}
