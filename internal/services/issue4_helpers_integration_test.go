//go:build integration

package services_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/techorionai/constellation-identity/internal/adapters/postgres"
	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

const (
	demoRedirect     = "https://demo.example.com/cb"
	demoPostLogout   = "https://demo.example.com/bye"
	adminRedirect    = "https://admin.example.com/cb"
	loopbackRedirect = "http://127.0.0.1/cb"
	demoScope        = "openid email offline_access demo:ticket:read"
	adminScopes      = "identity:user:read identity:user:write identity:role:read identity:role:assign identity:client:read identity:client:write identity:admin identity:session:read identity:session:revoke"
)

var (
	demoUI = testserver.PublicClient{
		ID: "demo-ui", App: "demo", RedirectURIs: []string{demoRedirect}, PostLogoutRedirectURIs: []string{demoPostLogout},
	}
	loopbackUI = testserver.PublicClient{
		ID: "loopback-ui", App: "demo", RedirectURIs: []string{loopbackRedirect, "http://localhost:3000/cb"},
	}
	adminUI = testserver.PublicClient{
		ID: "admin-ui", App: "identity", RedirectURIs: []string{adminRedirect},
	}
)

// fixture is a server with the public clients, an admin, and the manifest of
// the app demo.
type fixture struct {
	t     *testing.T
	a     *app
	clock *testserver.Clock
	// admin is the browser of the admin.
	admin *testserver.Web
	// serviceClient is the service client of the app demo.
	serviceClient testserver.ServiceClient
	// extraClient is the service client of the app extra.
	extraClient testserver.ServiceClient
}

// newFixture starts a server, makes the first admin, and publishes the manifest
// of the app demo.
func newFixture(t *testing.T, h *harness, opts ...testserver.Option) *fixture {
	t.Helper()
	clock := testserver.NewClock()
	demo := testserver.NewServiceClient(t, "demo", "demo")
	extra := testserver.NewServiceClient(t, "extra", "extra")
	all := append([]testserver.Option{
		testserver.WithPublicClients(t, []testserver.PublicClient{demoUI, loopbackUI, adminUI}, demo, extra),
		testserver.WithClock(clock), testserver.WithCORSCacheTTL(0),
	}, opts...)
	a := h.start(t, all...)
	f := &fixture{t: t, a: a, clock: clock, serviceClient: demo, extraClient: extra}
	web, resp := a.completeSetup(t, a.setupLink(t), "admin@example.com", "Admin", adminPassword)
	status(t, resp, http.StatusSeeOther, "setup")
	f.admin = web
	tok := token(t, a.Server, demo, "identity", "identity:manifest:publish")
	if resp, m := publish(t, a.Server, tok, "demo", demoManifestJSON(t)); resp.StatusCode != http.StatusOK {
		t.Fatalf("publish: %d %v", resp.StatusCode, m)
	}
	extraTok := token(t, a.Server, extra, "identity", "identity:manifest:publish")
	extraManifest := manifestJSON(t, "extra", []string{"extra:item:read", "extra:item:write"}, []string{"viewer", "editor"},
		map[string][]string{"viewer": {"extra:item:read"}, "editor": {"extra:item:read", "extra:item:write"}})
	if resp, m := publish(t, a.Server, extraTok, "extra", extraManifest); resp.StatusCode != http.StatusOK {
		t.Fatalf("publish extra: %d %v", resp.StatusCode, m)
	}
	return f
}

// login does the code flow of a user with an own browser. It returns the token
// response, the verifier, and the browser.
func (f *fixture) login(email, password, clientID, redirect, scope string) (testserver.TokenResponse, *testserver.Web) {
	f.t.Helper()
	web := f.a.NewWeb()
	return f.loginWith(web, email, password, clientID, redirect, scope), web
}

func (f *fixture) loginWith(web *testserver.Web, email, password, clientID, redirect, scope string) testserver.TokenResponse {
	f.t.Helper()
	p := testserver.NewPKCE(f.t)
	loc := web.CodeFlow(f.t, testserver.AuthorizeQuery(clientID, redirect, scope, p, nil), email, password)
	code := loc.Query().Get("code")
	if code == "" {
		f.t.Fatalf("login: no code in %s", loc)
	}
	f.a.ledger.add(&f.a.ledger.passwords, password)
	resp, tr := f.a.TokenRequest(f.t, testserver.CodeForm(clientID, code, redirect, p.Verifier))
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("token: status = %d, error = %s", resp.StatusCode, tr.Error)
	}
	for _, v := range []string{code, p.Verifier, tr.RefreshToken, tr.IDToken} {
		if v != "" {
			f.a.ledger.add(&f.a.ledger.flow, v)
		}
	}
	f.a.trackSession(web)
	return tr
}

// adminToken gives an access token of the admin for the app identity.
func (f *fixture) adminToken(scope string) string {
	f.t.Helper()
	tr, _ := f.login("admin@example.com", adminPassword, "admin-ui", adminRedirect, "openid "+scope)
	return tr.AccessToken
}

// api calls an admin operation with a bearer token.
func (f *fixture) api(tok, method, path string, body any) (testserver.Response, map[string]any) {
	f.t.Helper()
	var raw string
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			f.t.Fatal(err)
		}
		raw = string(b)
	}
	resp, b := f.a.Do(f.t, method, path, tok, raw)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp, m
}

// newUser makes a user with the admin API, accepts the invite, assigns the
// roles, and returns the ID.
func (f *fixture) newUser(tok, email, password string, roles ...string) string {
	f.t.Helper()
	resp, m := f.api(tok, http.MethodPost, "/v1/users", map[string]string{"email": email, "name": "User " + email})
	if resp.StatusCode != http.StatusCreated {
		f.t.Fatalf("create user: %d %v", resp.StatusCode, m)
	}
	user := m["user"].(map[string]any)
	invite := m["invite"].(map[string]any)["url"].(string)
	f.a.ledger.add(&f.a.ledger.invites, testserver.TokenOf(f.t, invite))
	web := f.a.NewWeb()
	f.a.ledger.add(&f.a.ledger.passwords, password)
	resp, _ = web.PostForm(f.t, "/invite", url.Values{"token": {testserver.TokenOf(f.t, invite)}, "password": {password}, "password2": {password}})
	status(f.t, resp, http.StatusSeeOther, "accept invite")
	id := user["id"].(string)
	for _, r := range roles {
		resp, m := f.api(tok, http.MethodPut, "/v1/users/"+id+"/roles/"+r, nil)
		if resp.StatusCode != http.StatusOK {
			f.t.Fatalf("assign %s: %d %v", r, resp.StatusCode, m)
		}
	}
	return id
}

// sessionID returns the ID of the session of a browser.
func (f *fixture) sessionID(web *testserver.Web) string {
	f.t.Helper()
	var id string
	row := f.a.Pool(f.t).QueryRow(ctx, `SELECT id FROM sessions WHERE token_hash = encode(sha256($1::bytea), 'hex')`, web.Cookie(pages.CookieName))
	if err := row.Scan(&id); err != nil {
		f.t.Fatalf("session of the cookie: %v", err)
	}
	return id
}

func (f *fixture) countWhere(query string, args ...any) int {
	f.t.Helper()
	return count(f.t, f.a.Server, query, args...)
}

// advance moves the clock of the server.
func (f *fixture) advance(d time.Duration) { f.clock.Advance(d) }

func postgresRefresh(pool *pgxpool.Pool) *postgres.RefreshTokens {
	return postgres.NewRefreshTokens(pool)
}

// counterValue returns the sum of a counter of all attribute sets.
func counterValue(t *testing.T, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := metricReader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok && m.Name == name {
				for _, dp := range sum.DataPoints {
					total += dp.Value
				}
			}
		}
	}
	return total
}
