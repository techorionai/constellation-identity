//go:build integration

package services_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
	swa "github.com/techorionai/constellation-identity/resources/test/webauthn"
)

const passkeyScope = "openid identity:mfa:manage_own"

// passkeyUser is a user with a password, a browser, and a software authenticator.
type passkeyUser struct {
	id, email, password string
	web                 *testserver.Web
	key                 *swa.Authenticator
}

// newAuthenticator makes a software authenticator for the server of the fixture.
func (f *fixture) newAuthenticator(alg swa.Algorithm) *swa.Authenticator {
	return swa.New(f.a.Config.Issuer, "localhost", alg)
}

// jsonPost posts a JSON body and returns the status and the decoded body.
func (f *fixture) jsonPost(web *testserver.Web, path string, body []byte) (testserver.Response, map[string]any, []byte) {
	f.t.Helper()
	resp, b := web.PostJSON(f.t, path, body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp, m, b
}

// registerPasskey does the registration on the page of the passkeys: the
// options, the response of the authenticator, and the finish step. It returns
// the answer of the finish step.
func (f *fixture) registerPasskey(web *testserver.Web, key *swa.Authenticator, name string, opts ...swa.CallOption) (testserver.Response, map[string]any) {
	f.t.Helper()
	req, _ := json.Marshal(map[string]string{"name": name})
	resp, m, raw := f.jsonPost(web, "/account/passkeys/options", req)
	status(f.t, resp, http.StatusOK, "POST /account/passkeys/options")
	if resp.Header.Get("Cache-Control") != "no-store" {
		f.t.Fatal("the options need no-store")
	}
	_ = m
	response := key.Create(f.t, raw, opts...)
	f.trackWebAuthn(raw, key)
	resp, m, _ = f.jsonPost(web, "/account/passkeys/finish", response)
	return resp, m
}

// trackWebAuthn remembers the challenge, the credential IDs, and the user
// handles of a ceremony. No log record and no span may hold them.
func (f *fixture) trackWebAuthn(options []byte, key *swa.Authenticator) {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err == nil && o.PublicKey.Challenge != "" {
		f.a.ledger.add(&f.a.ledger.flow, o.PublicKey.Challenge)
	}
	enc := base64.RawURLEncoding
	for _, c := range key.Creds {
		f.a.ledger.add(&f.a.ledger.flow, enc.EncodeToString(c.ID))
		f.a.ledger.add(&f.a.ledger.flow, enc.EncodeToString(c.UserHandle))
	}
}

// newPasskeyUser makes a user with a password and a fresh session, and
// registers one passkey with the name "First".
func (f *fixture) newPasskeyUser(email string, alg swa.Algorithm, roles ...string) *passkeyUser {
	f.t.Helper()
	return f.newPasskeyUserWith(f.adminToken(adminScopes), email, alg, roles...)
}

// newPasskeyUserWith is newPasskeyUser with the admin token that makes the user.
func (f *fixture) newPasskeyUserWith(adminTok, email string, alg swa.Algorithm, roles ...string) *passkeyUser {
	f.t.Helper()
	id := f.newUser(adminTok, email, userPassword, roles...)
	web := f.a.NewWeb()
	f.passwordLogin(web, email, userPassword, "/login/done")
	u := &passkeyUser{id: id, email: email, password: userPassword, web: web, key: f.newAuthenticator(alg)}
	resp, m := f.registerPasskey(web, u.key, "First")
	status(f.t, resp, http.StatusOK, "register the first passkey")
	if m["redirect"] != "/account/passkeys" {
		f.t.Fatalf("finish = %v", m)
	}
	return u
}

// passkeyLogin does the login with no password on the pages. It returns the
// answer of the finish step.
func (f *fixture) passkeyLogin(web *testserver.Web, key *swa.Authenticator, authRequest string, opts ...swa.CallOption) (testserver.Response, map[string]any) {
	f.t.Helper()
	req, _ := json.Marshal(map[string]string{"authRequest": authRequest})
	resp, _, raw := f.jsonPost(web, "/login/passkey/options", req)
	status(f.t, resp, http.StatusOK, "POST /login/passkey/options")
	if web.Cookie(pages.WebAuthnCookieName) == "" {
		f.t.Fatal("the options step must set the cookie of the ceremony")
	}
	f.a.ledger.add(&f.a.ledger.flow, web.Cookie(pages.WebAuthnCookieName))
	response := key.Get(f.t, raw, opts...)
	f.trackWebAuthn(raw, key)
	resp, m, _ := f.jsonPost(web, "/login/passkey/finish", response)
	if web.Cookie(pages.WebAuthnCookieName) != "" {
		f.t.Fatal("the finish step must remove the cookie of the ceremony")
	}
	return resp, m
}

// passkeyCodeFlow does the code flow of a user with a passkey and no password.
func (f *fixture) passkeyCodeFlow(web *testserver.Web, key *swa.Authenticator, clientID, redirect, scope string, extra map[string]string) testserver.TokenResponse {
	f.t.Helper()
	p := testserver.NewPKCE(f.t)
	q := map[string]string{"prompt": "login"}
	for k, v := range extra {
		q[k] = v
	}
	resp := web.Authorize(f.t, testserver.AuthorizeQuery(clientID, redirect, scope, p, q))
	loc := testserver.Location(f.t, resp)
	id := loc.Query().Get("authRequest")
	if !strings.HasPrefix(loc.Path, "/login") || id == "" {
		f.t.Fatalf("authorize: Location = %s", loc)
	}
	f.a.ledger.add(&f.a.ledger.flow, id)
	resp, m := f.passkeyLogin(web, key, id)
	status(f.t, resp, http.StatusOK, "passkey login")
	next, _ := m["redirect"].(string)
	if !strings.HasPrefix(next, "/oauth/authorize/continue?authRequest=") {
		f.t.Fatalf("passkey login: redirect = %q", next)
	}
	f.a.trackSession(web)
	resp, _ = web.Get(f.t, next)
	status(f.t, resp, http.StatusFound, "continue")
	return f.exchangeCode(testserver.Location(f.t, resp), p, clientID, redirect)
}

// passkeyToken gives an access token of a user that logged in with a passkey.
func (f *fixture) passkeyToken(u *passkeyUser, scope string) string {
	f.t.Helper()
	return f.passkeyCodeFlow(f.a.NewWeb(), u.key, "admin-ui", adminRedirect, scope, nil).AccessToken
}

// passkeyRows returns the number of stored passkeys of a user.
func (f *fixture) passkeyRows(userID string) int {
	f.t.Helper()
	return f.countWhere(`SELECT count(*) FROM webauthn_credentials WHERE user_id = $1`, userID)
}

// passkeyIDs returns the IDs of the passkeys of a user in the order of the list.
func (f *fixture) passkeyIDs(userID string) []string {
	f.t.Helper()
	rows, err := f.a.Pool(f.t).Query(ctx, `SELECT id FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

// apiWith calls an operation with a bearer token and a raw body.
func (f *fixture) apiRaw(tok, method, path, body string) (testserver.Response, map[string]any) {
	f.t.Helper()
	resp, b := f.a.Do(f.t, method, path, tok, body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp, m
}

// formValues makes the form of a name.
func nameForm(name string) url.Values { return url.Values{"name": {name}} }
