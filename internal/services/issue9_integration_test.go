//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/techorionai/constellation-platform-go/auth"
	"github.com/techorionai/constellation-platform-go/auth/introspect"
	"github.com/techorionai/constellation-platform-go/retention"

	"github.com/techorionai/constellation-identity/internal/adapters/postgres"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/migrations"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

const (
	manageOwn      = "identity:api_token:manage_own"
	apiAdminScopes = adminScopes + " identity:api_token:read identity:api_token:revoke " + manageOwn
	demoAndExtra   = "demo:ticket:read extra:item:read"
)

// tokenFixture is a server with a limit of 5 active tokens for each user.
func tokenFixture(t *testing.T, h *harness) *fixture {
	t.Helper()
	return newFixture(t, h, testserver.WithConfigure(func(c *config.Config) { c.APIToken.MaxPerUser = 5 }))
}

// apiUser makes an active user with the roles of the apps demo and extra, and
// returns the ID and an access token for the app identity.
func (f *fixture) apiUser(admin, name string, roles ...string) (id, access string) {
	f.t.Helper()
	email := name + "@example.com"
	id = f.newUser(admin, email, userPassword, roles...)
	return id, f.userAccess(email)
}

func (f *fixture) userAccess(email string) string {
	f.t.Helper()
	tr, _ := f.login(email, userPassword, "admin-ui", adminRedirect, "openid "+manageOwn)
	return tr.AccessToken
}

// createToken makes a token and remembers its value for the secret check.
func (f *fixture) createToken(access, name, scope string, days int) (testserver.Response, map[string]any) {
	f.t.Helper()
	resp, m := f.a.CreateAPIToken(f.t, access, name, scope, days)
	if v, ok := m["token"].(string); ok {
		f.a.ledger.add(&f.a.ledger.apiTokens, v)
	}
	return resp, m
}

func (f *fixture) mustCreate(access, name, scope string) (id, value string) {
	f.t.Helper()
	resp, m := f.createToken(access, name, scope, 0)
	if resp.StatusCode != http.StatusCreated {
		f.t.Fatalf("create token: %d %v", resp.StatusCode, m)
	}
	return m["id"].(string), testserver.APITokenOf(f.t, m)
}

// introspectAt sends an introspection request. The client check of the server
// uses the real clock, so the assertion has the real time. The check of the
// token uses the clock of the test.
func (f *fixture) introspectAt(c testserver.ServiceClient, value string) (testserver.Response, map[string]any) {
	f.t.Helper()
	return f.a.Introspect(f.t, c, value)
}

func requireInactive(t *testing.T, resp testserver.Response, m map[string]any, what string) {
	t.Helper()
	if resp.StatusCode != http.StatusOK || len(m) != 1 || m["active"] != false {
		t.Fatalf("%s: status %d, body %v, want {active:false}", what, resp.StatusCode, m)
	}
}

func scopeList(m map[string]any) string {
	s, _ := m["scope"].(string)
	return s
}

func TestIssue9Integration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := tokenFixture(t, h)
	admin := f.adminToken(apiAdminScopes)
	demo, extra := f.serviceClient, f.extraClient

	// I2: a user with no roles gets a token with the scope of the implicit role.
	t.Run("I2_user_with_no_roles", func(t *testing.T) {
		id, _ := f.apiUser(admin, "noroles")
		tr, _ := f.login("noroles@example.com", userPassword, "admin-ui", adminRedirect, "openid "+manageOwn)
		_, claims := testserver.JWTClaims(t, tr.AccessToken)
		if claims["scope"] != manageOwn || claims["aud"] != "identity" {
			t.Fatalf("claims = %v", claims)
		}
		// U16 and U16a on the real repository.
		repo := postgres.NewUserRoles(f.a.Pool(t))
		got, err := repo.GrantedPermissions(ctx, id, domain.ImplicitUserRoles(domain.UserActive)...)
		if err != nil || len(got) != 1 || got[0] != manageOwn {
			t.Fatalf("active: %v, %v", got, err)
		}
		if got, err := repo.GrantedPermissions(ctx, id, domain.ImplicitUserRoles(domain.UserInvited)...); err != nil || len(got) != 0 {
			t.Fatalf("invited: %v, %v", got, err)
		}
		if got, err := repo.GrantedPermissions(ctx, id); err != nil || len(got) != 0 {
			t.Fatalf("no implicit role: %v, %v", got, err)
		}
	})

	// I3: create, list, and revoke.
	t.Run("I3_create_list_revoke", func(t *testing.T) {
		_, access := f.apiUser(admin, "i3", "demo:agent")
		resp, m := f.createToken(access, "ci", "demo:ticket:read", 0)
		if resp.StatusCode != http.StatusCreated || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
			t.Fatalf("create: %d %v %v", resp.StatusCode, resp.Header, m)
		}
		value := testserver.APITokenOf(t, m)
		if !strings.HasPrefix(value, "cpat_") || len(value) != 48 {
			t.Fatalf("token = %q", value)
		}
		id := m["id"].(string)
		resp, body := f.a.Do(t, http.MethodGet, "/v1/me/api-tokens", access, "")
		if resp.StatusCode != http.StatusOK || strings.Contains(string(body), value) || strings.Contains(string(body), domain.HashSecret(value)) ||
			strings.Contains(string(body), `"token"`) || !strings.Contains(string(body), id) {
			t.Fatalf("list: %d %s", resp.StatusCode, body)
		}
		// A cpat_ value on /v1 gives 401 (U12a).
		if resp, _ := f.a.Do(t, http.MethodGet, "/v1/me/api-tokens", value, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("cpat_ value on /v1: %d", resp.StatusCode)
		}
		if resp, _ := f.a.Do(t, http.MethodDelete, "/v1/me/api-tokens/"+id, access, ""); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke: %d", resp.StatusCode)
		}
		resp, body = f.a.Do(t, http.MethodGet, "/v1/me/api-tokens", access, "")
		m = decode(t, body)
		if len(items(m)) != 1 || items(m)[0]["revokedAt"] == nil {
			t.Fatalf("list after revoke: %d %s", resp.StatusCode, body)
		}
		var create, revoke bool
		for _, r := range f.a.logs.Records(t) {
			if r["event"] == "identity.api_token.change" && r["token_id"] == id {
				create = create || r["operation"] == "create"
				revoke = revoke || r["operation"] == "revoke"
			}
		}
		if !create || !revoke {
			t.Fatalf("log records: create %v, revoke %v", create, revoke)
		}
	})

	// I4 and I5: the caller sees only the scopes of its app.
	t.Run("I4_I5_caller_app", func(t *testing.T) {
		id, access := f.apiUser(admin, "i4", "demo:agent", "extra:viewer")
		tid, value := f.mustCreate(access, "both", demoAndExtra)
		resp, m := f.a.Introspect(t, demo, value)
		if resp.StatusCode != http.StatusOK || m["active"] != true || scopeList(m) != "demo:ticket:read" || m["aud"] != "demo" ||
			m["sub"] != id || m["jti"] != tid || m["token_type"] != "api_token" || m["principal_type"] != "user" {
			t.Fatalf("demo: %d %v", resp.StatusCode, m)
		}
		if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
			t.Fatalf("headers = %v", resp.Header)
		}
		// exp and iat are JSON integers in Unix seconds.
		_, raw := f.a.Post(t, "/oauth/introspect", testserver.IntrospectForm(f.a.Assertion(t, demo, nil), value).Encode())
		var typed struct {
			Exp int64 `json:"exp"`
			Iat int64 `json:"iat"`
		}
		if err := json.Unmarshal(raw, &typed); err != nil || typed.Iat < time.Now().Add(-time.Minute).Unix() || typed.Exp-typed.Iat < 89*24*3600 {
			t.Fatalf("exp and iat: %s, %v", raw, err)
		}
		resp, m = f.a.Introspect(t, extra, value)
		if resp.StatusCode != http.StatusOK || m["active"] != true || scopeList(m) != "extra:item:read" || m["aud"] != "extra" {
			t.Fatalf("extra: %d %v", resp.StatusCode, m)
		}
		// I5: a token with scopes of the app demo only is not active for the app extra.
		_, onlyDemo := f.mustCreate(access, "demo only", "demo:ticket:read")
		resp, m = f.a.Introspect(t, extra, onlyDemo)
		requireInactive(t, resp, m, "other app")
	})

	// The errors of the introspection endpoint.
	t.Run("I4a_introspect_errors", func(t *testing.T) {
		_, access := f.apiUser(admin, "i4a", "demo:agent")
		_, value := f.mustCreate(access, "t", "demo:ticket:read")
		form := testserver.IntrospectForm(f.a.Assertion(t, demo, nil), value)
		repeated := testserver.IntrospectForm(f.a.Assertion(t, demo, nil), value)
		repeated.Add("token", value)
		secret := testserver.IntrospectForm(f.a.Assertion(t, demo, nil), value)
		secret.Set("client_secret", "x")
		noType := testserver.IntrospectForm(f.a.Assertion(t, demo, nil), value)
		noType.Del("client_assertion_type")
		public := testserver.IntrospectForm(f.a.Assertion(t, demo, func(c, _ map[string]any) { c["iss"], c["sub"] = "admin-ui", "admin-ui" }), value)
		for name, tc := range map[string]struct {
			form   map[string][]string
			status int
			code   string
		}{
			"repeated field": {repeated, http.StatusBadRequest, "invalid_request"},
			"client secret":  {secret, http.StatusUnauthorized, "invalid_client"},
			"no type":        {noType, http.StatusUnauthorized, "invalid_client"},
			"public client":  {public, http.StatusUnauthorized, "invalid_client"},
		} {
			resp, m := f.a.PostIntrospect(t, tc.form)
			if resp.StatusCode != tc.status || m["error"] != tc.code {
				t.Errorf("%s: %d %v", name, resp.StatusCode, m)
			}
		}
		// The Authorization header with the scheme Basic.
		resp, b := f.a.PostAuthorization(t, "/oauth/introspect", form, "Basic eDp5")
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(b), "invalid_client") {
			t.Errorf("basic: %d %s", resp.StatusCode, b)
		}
		// The first request is fine.
		if resp, m := f.a.PostIntrospect(t, testserver.IntrospectForm(f.a.Assertion(t, demo, nil), value)); resp.StatusCode != http.StatusOK || m["active"] != true {
			t.Errorf("valid request: %d %v", resp.StatusCode, m)
		}
		// A bad token format gives the same answer as an unknown token.
		resp2, m2 := f.a.Introspect(t, demo, "cpat_"+strings.Repeat("A", 43))
		requireInactive(t, resp2, m2, "unknown token")
		resp2, m2 = f.a.Introspect(t, demo, "not a token")
		requireInactive(t, resp2, m2, "bad format")
	})

	// I6: a revoked token, an expired token, and a user who is disabled are not
	// active. The test uses its own server to move the clock.
	t.Run("I6_inactive_tokens", func(t *testing.T) {
		g := tokenFixture(t, h)
		gadmin := g.adminToken(apiAdminScopes)
		_, selfAccess := g.apiUser(gadmin, "self", "demo:agent")
		selfID, selfValue := g.mustCreate(selfAccess, "self", "demo:ticket:read")
		if resp, m := g.introspectAt(g.serviceClient, selfValue); m["active"] != true {
			t.Fatalf("before: %d %v", resp.StatusCode, m)
		}
		if resp, _ := g.a.Do(t, http.MethodDelete, "/v1/me/api-tokens/"+selfID, selfAccess, ""); resp.StatusCode != http.StatusNoContent {
			t.Fatal("self revoke")
		}
		resp, m := g.introspectAt(g.serviceClient, selfValue)
		requireInactive(t, resp, m, "self revoke")

		_, userAccess := g.apiUser(gadmin, "adminrev", "demo:agent")
		adminTokenID, adminValue := g.mustCreate(userAccess, "t", "demo:ticket:read")
		if resp, b := g.a.Do(t, http.MethodDelete, "/v1/api-tokens/"+adminTokenID, gadmin, ""); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("admin revoke: %d %s", resp.StatusCode, b)
		}
		resp, m = g.introspectAt(g.serviceClient, adminValue)
		requireInactive(t, resp, m, "admin revoke")

		disabledID, disabledAccess := g.apiUser(gadmin, "disabled", "demo:agent")
		_, v1 := g.mustCreate(disabledAccess, "one", "demo:ticket:read")
		_, v2 := g.mustCreate(disabledAccess, "two", "demo:ticket:read")
		_, expireValue := g.mustCreate(selfAccess, "expiring", "demo:ticket:read")
		if resp, m := g.api(gadmin, http.MethodPatch, "/v1/users/"+disabledID, map[string]any{"disabled": true}); resp.StatusCode != http.StatusOK {
			t.Fatalf("disable: %d %v", resp.StatusCode, m)
		}
		for _, v := range []string{v1, v2} {
			resp, m = g.introspectAt(g.serviceClient, v)
			requireInactive(t, resp, m, "disabled user")
		}
		found := false
		for _, r := range g.a.logs.Records(t) {
			if r["operation"] == "Users_update" && r["target_id"] == disabledID && r["api_tokens_revoked"] == float64(2) {
				found = true
			}
		}
		if !found {
			t.Fatal("the disable record has no api_tokens_revoked=2")
		}
		// An enable does not restore the tokens.
		if resp, _ := g.api(gadmin, http.MethodPatch, "/v1/users/"+disabledID, map[string]any{"disabled": false}); resp.StatusCode != http.StatusOK {
			t.Fatal("enable")
		}
		resp, m = g.introspectAt(g.serviceClient, v1)
		requireInactive(t, resp, m, "enabled user")
		// The token expires with the clock of the server.
		if resp, m := g.introspectAt(g.serviceClient, expireValue); m["active"] != true {
			t.Fatalf("before the expiry: %d %v", resp.StatusCode, m)
		}
		g.advance(91 * 24 * time.Hour)
		resp, m = g.introspectAt(g.serviceClient, expireValue)
		requireInactive(t, resp, m, "expired token")
	})

	// I7: a role that goes away takes the scope away.
	t.Run("I7_role_removed", func(t *testing.T) {
		id, access := f.apiUser(admin, "i7", "demo:agent")
		_, value := f.mustCreate(access, "t", "demo:ticket:read")
		if resp, m := f.a.Introspect(t, demo, value); m["active"] != true {
			t.Fatalf("before: %d %v", resp.StatusCode, m)
		}
		if resp, _ := f.api(admin, http.MethodDelete, "/v1/users/"+id+"/roles/demo:agent", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove role: %d", resp.StatusCode)
		}
		resp, m := f.a.Introspect(t, demo, value)
		requireInactive(t, resp, m, "role removed")
	})

	// I8, I8a, I9: a service that uses auth.ByFormat and auth/introspect.
	t.Run("I8_verifier_in_a_service", func(t *testing.T) {
		g := tokenFixture(t, h)
		gadmin := g.adminToken(apiAdminScopes)
		_, access := g.apiUser(gadmin, "svc", "demo:agent")
		tokenID, value := g.mustCreate(access, "t", "demo:ticket:read")
		var offset time.Duration
		var mu sync.Mutex
		now := func() time.Time { mu.Lock(); defer mu.Unlock(); return time.Now().Add(offset) }
		service := func(c testserver.ServiceClient, audience string) *httptest.Server {
			v, err := introspect.New(introspect.Config{
				Issuer: g.a.Config.Issuer, IntrospectURL: g.a.PublicURL + "/oauth/introspect", Audience: audience,
				CacheTTL: time.Second, InactiveTTL: 0, CacheSize: 100, InactiveCacheSize: 10, MaxConcurrent: 16,
				HTTPTimeout: 5 * time.Second, AllowInsecureHTTP: true,
			}, g.a.TokenSource(t, c), introspect.WithClock(now))
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			mux.Handle("/work", auth.Middleware(auth.ByFormat(nil, v))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, _ := auth.PrincipalFromContext(r.Context())
				_, _ = fmt.Fprintf(w, "%s %s %s", p.ID, strings.Join(p.Scopes, ","), p.TokenType)
			})))
			s := httptest.NewServer(mux)
			t.Cleanup(s.Close)
			return s
		}
		call := func(s *httptest.Server) (int, string, http.Header) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+"/work", nil)
			req.Header.Set("Authorization", "Bearer "+value)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var b strings.Builder
			buf := make([]byte, 512)
			for {
				n, err := resp.Body.Read(buf)
				b.Write(buf[:n])
				if err != nil {
					break
				}
			}
			return resp.StatusCode, b.String(), resp.Header
		}
		svc := service(g.serviceClient, "demo")
		other := service(g.extraClient, "extra")
		if code, body, _ := call(svc); code != http.StatusOK || !strings.Contains(body, "demo:ticket:read") || !strings.Contains(body, "api_token") {
			t.Fatalf("active token: %d %s", code, body)
		}
		// I8a: a service of another app gets 401.
		if code, _, _ := call(other); code != http.StatusUnauthorized {
			t.Fatalf("other app: %d", code)
		}
		if resp, _ := g.a.Do(t, http.MethodDelete, "/v1/me/api-tokens/"+tokenID, access, ""); resp.StatusCode != http.StatusNoContent {
			t.Fatal("revoke")
		}
		mu.Lock()
		offset = 2 * time.Second
		mu.Unlock()
		if code, _, _ := call(svc); code != http.StatusUnauthorized {
			t.Fatalf("after the revoke and the cache time: %d", code)
		}
		// I9: the identity server stops. A token that is not in the cache gives 503.
		_, value2 := g.mustCreate(access, "t2", "demo:ticket:read")
		value = value2
		g.a.Stop()
		code, _, header := call(svc)
		if code != http.StatusServiceUnavailable || header.Get("Retry-After") == "" {
			t.Fatalf("identity stopped: %d %v", code, header)
		}
	})

	// I10: 20 creates at the same time with a limit of 5.
	t.Run("I10_concurrent_creates", func(t *testing.T) {
		id, access := f.apiUser(admin, "i10", "demo:agent")
		var wg sync.WaitGroup
		codes := make([]string, 20)
		statuses := make([]int, 20)
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, m := f.a.CreateAPIToken(t, access, fmt.Sprint("t", i), "demo:ticket:read", 0)
				statuses[i], codes[i] = resp.StatusCode, code(m)
				if v, ok := m["token"].(string); ok {
					f.a.ledger.add(&f.a.ledger.apiTokens, v)
				}
			}()
		}
		wg.Wait()
		created, limited := 0, 0
		for i := range statuses {
			switch {
			case statuses[i] == http.StatusCreated:
				created++
			case statuses[i] == http.StatusUnprocessableEntity && codes[i] == "token_limit":
				limited++
			}
		}
		if created != 5 || limited != 15 || f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1`, id) != 5 {
			t.Fatalf("created %d, limited %d, statuses %v", created, limited, statuses)
		}
	})

	// I11: the admin lists and revokes the tokens of a user.
	t.Run("I11_admin_operations", func(t *testing.T) {
		id, access := f.apiUser(admin, "i11", "demo:agent")
		tid, _ := f.mustCreate(access, "t", "demo:ticket:read")
		resp, m := f.api(admin, http.MethodGet, "/v1/users/"+id+"/api-tokens", nil)
		if resp.StatusCode != http.StatusOK || len(items(m)) != 1 || items(m)[0]["id"] != tid {
			t.Fatalf("list: %d %v", resp.StatusCode, m)
		}
		// A user token with the scope of the own tokens only gets 403.
		if resp, _ := f.api(access, http.MethodGet, "/v1/users/"+id+"/api-tokens", nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("list without the permission: %d", resp.StatusCode)
		}
		if resp, _ := f.api(access, http.MethodDelete, "/v1/api-tokens/"+tid, nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("revoke without the permission: %d", resp.StatusCode)
		}
		resp, m = f.api(admin, http.MethodDelete, "/v1/api-tokens/00000000-0000-4000-8000-0000000000f0", nil)
		if resp.StatusCode != http.StatusNotFound || code(m) != "api_token_not_found" {
			t.Fatalf("unknown token: %d %v", resp.StatusCode, m)
		}
		resp, m = f.api(admin, http.MethodGet, "/v1/users/00000000-0000-4000-8000-0000000000f1/api-tokens", nil)
		if resp.StatusCode != http.StatusNotFound || code(m) != "user_not_found" {
			t.Fatalf("unknown user: %d %v", resp.StatusCode, m)
		}
		if resp, m = f.api(admin, http.MethodGet, "/v1/users/not-a-uuid/api-tokens", nil); resp.StatusCode != http.StatusNotFound || code(m) != "user_not_found" {
			t.Fatalf("bad user ID: %d %v", resp.StatusCode, m)
		}
		if resp, _ := f.api(admin, http.MethodDelete, "/v1/api-tokens/"+tid, nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke: %d", resp.StatusCode)
		}
		resp, m = f.api(admin, http.MethodGet, "/v1/users/"+id+"/api-tokens", nil)
		if items(m)[0]["revokedAt"] == nil {
			t.Fatalf("list after the revoke: %d %v", resp.StatusCode, m)
		}
	})

	// I12: last_used_at is set at the first introspection, and not again in the
	// same hour.
	t.Run("I12_last_used", func(t *testing.T) {
		_, access := f.apiUser(admin, "i12", "demo:agent")
		tid, value := f.mustCreate(access, "t", "demo:ticket:read")
		read := func() *time.Time {
			var at *time.Time
			if err := f.a.Pool(t).QueryRow(ctx, `SELECT last_used_at FROM api_tokens WHERE id = $1`, tid).Scan(&at); err != nil {
				t.Fatal(err)
			}
			return at
		}
		if read() != nil {
			t.Fatal("last_used_at is set before the first use")
		}
		f.a.Introspect(t, demo, value)
		first := read()
		if first == nil {
			t.Fatal("last_used_at is not set")
		}
		time.Sleep(20 * time.Millisecond)
		f.a.Introspect(t, demo, value)
		if second := read(); second == nil || !second.Equal(*first) {
			t.Fatalf("last_used_at changed: %v -> %v", first, second)
		}
	})

	// I13: the retention job removes the rows that ended before the period.
	t.Run("I13_retention", func(t *testing.T) {
		id, _ := f.apiUser(admin, "i13", "demo:agent")
		pool := f.a.Pool(t)
		seed := []string{
			// hash, name, expires_at, revoked_at
			`('r-exp-old', 'expired long ago', now() - interval '10 days', NULL)`,
			`('r-rev-old', 'revoked long ago', now() + interval '30 days', now() - interval '9 days')`,
			`('r-exp-new', 'expired lately', now() - interval '1 day', NULL)`,
			`('r-rev-new', 'revoked lately', now() + interval '30 days', now() - interval '1 day')`,
			`('r-active', 'active', now() + interval '30 days', NULL)`,
		}
		for i, row := range seed {
			q := fmt.Sprintf(`INSERT INTO api_tokens (id, token_hash, user_id, name, scope, created_at, expires_at, revoked_at)
				SELECT '00000000-0000-4000-8000-00000000a0%02d', h, '%s', n, 'demo:ticket:read', now() - interval '20 days', e, r
				FROM (VALUES %s) AS v (h, n, e, r)`, i, id, strings.Replace(row, "NULL", "NULL::timestamptz", 1))
			if _, err := pool.Exec(ctx, q); err != nil {
				t.Fatalf("seed: %v\n%s", err, q)
			}
		}
		n, err := postgres.NewAPITokenPurger(pool).Purge(ctx, retention.PurgeParams{Before: time.Now().Add(-7 * 24 * time.Hour), Limit: 100})
		if err != nil || n != 2 {
			t.Fatalf("purged = %d, %v, want 2", n, err)
		}
		for _, name := range []string{"expired long ago", "revoked long ago"} {
			if f.countWhere(`SELECT count(*) FROM api_tokens WHERE name = $1`, name) != 0 {
				t.Errorf("%s is not removed", name)
			}
		}
		for _, name := range []string{"expired lately", "revoked lately", "active"} {
			if f.countWhere(`SELECT count(*) FROM api_tokens WHERE name = $1`, name) != 1 {
				t.Errorf("%s is removed", name)
			}
		}
	})

	// I15: the exploit steps of finding P5. A user who is disabled cannot make a
	// token with an access token that is not expired.
	t.Run("I15_disabled_user_create", func(t *testing.T) {
		id, access := f.apiUser(admin, "i15", "demo:agent")
		if resp, _ := f.api(admin, http.MethodPatch, "/v1/users/"+id, map[string]any{"disabled": true}); resp.StatusCode != http.StatusOK {
			t.Fatal("disable")
		}
		resp, m := f.createToken(access, "late", "demo:ticket:read", 0)
		if resp.StatusCode != http.StatusForbidden || code(m) != "user_token_required" {
			t.Fatalf("create after the disable: %d %v", resp.StatusCode, m)
		}
		if f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1`, id) != 0 {
			t.Fatal("a row exists")
		}
		if resp, _ := f.api(admin, http.MethodPatch, "/v1/users/"+id, map[string]any{"disabled": false}); resp.StatusCode != http.StatusOK {
			t.Fatal("enable")
		}
		if f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL`, id) != 0 {
			t.Fatal("a token is active after the enable")
		}
	})

	// I16: the exploit steps of finding P11. A loop of create and revoke stops
	// at 10 times the limit.
	t.Run("I16_total_row_limit", func(t *testing.T) {
		id, access := f.apiUser(admin, "i16", "demo:agent")
		for i := range 50 {
			tid, _ := f.mustCreate(access, fmt.Sprint("loop", i), "demo:ticket:read")
			if resp, _ := f.a.Do(t, http.MethodDelete, "/v1/me/api-tokens/"+tid, access, ""); resp.StatusCode != http.StatusNoContent {
				t.Fatalf("revoke %d", i)
			}
		}
		resp, m := f.createToken(access, "over", "demo:ticket:read", 0)
		if resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "token_limit" {
			t.Fatalf("create after 50 rows: %d %v", resp.StatusCode, m)
		}
		if n := f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1`, id); n != 50 {
			t.Fatalf("rows = %d, want 50", n)
		}
	})

	// I17: the exploit steps of finding P12. An admin cannot make a token with
	// an identity key.
	t.Run("I17_identity_keys", func(t *testing.T) {
		before := f.countWhere(`SELECT count(*) FROM api_tokens`)
		for _, scope := range []string{"identity:admin", manageOwn} {
			resp, m := f.createToken(admin, "root", scope, 0)
			if resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "scope_not_granted" {
				t.Fatalf("%s: %d %v", scope, resp.StatusCode, m)
			}
		}
		if f.countWhere(`SELECT count(*) FROM api_tokens`) != before {
			t.Fatal("a row exists")
		}
		// Old rows with an identity key never show in an introspection.
		id, access := f.apiUser(admin, "i17", "demo:agent")
		_, value := f.mustCreate(access, "t", "demo:ticket:read")
		if _, err := f.a.Pool(t).Exec(ctx, `UPDATE api_tokens SET scope = 'identity:admin demo:ticket:read' WHERE user_id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if _, m := f.a.Introspect(t, demo, value); scopeList(m) != "demo:ticket:read" {
			t.Fatalf("scope = %v", m)
		}
	})

	// I18: the implicit role in the role API.
	t.Run("I18_implicit_role_api", func(t *testing.T) {
		id, _ := f.apiUser(admin, "i18")
		check := func(what string) {
			t.Helper()
			resp, m := f.api(admin, http.MethodGet, "/v1/users/"+id+"/roles", nil)
			list := items(m)
			if resp.StatusCode != http.StatusOK || len(list) != 1 || list[0]["role"] != "identity:user" || list[0]["source"] != "config" {
				t.Fatalf("%s: %d %v", what, resp.StatusCode, m)
			}
		}
		check("list")
		resp, m := f.api(admin, http.MethodPut, "/v1/users/"+id+"/roles/identity:user", nil)
		if resp.StatusCode != http.StatusOK || m["source"] != "config" || m["role"] != "identity:user" {
			t.Fatalf("assign: %d %v", resp.StatusCode, m)
		}
		check("after assign")
		if resp, _ := f.api(admin, http.MethodDelete, "/v1/users/"+id+"/roles/identity:user", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove: %d", resp.StatusCode)
		}
		check("after remove")
		if f.countWhere(`SELECT count(*) FROM user_roles WHERE user_id = $1`, id) != 0 {
			t.Fatal("a role row exists")
		}
	})

	// I14: no log record and no span holds a token value or a hash.
	t.Run("I14_no_secrets_in_telemetry", func(t *testing.T) {
		h.ledger.mu.Lock()
		defer h.ledger.mu.Unlock()
		if len(h.ledger.apiTokens) < 10 {
			t.Fatalf("the ledger has %d tokens", len(h.ledger.apiTokens))
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
				spans += e.Name + "\n"
				for _, a := range e.Attributes {
					spans += string(a.Key) + "=" + a.Value.String() + "\n"
				}
			}
		}
		for _, v := range h.ledger.apiTokens {
			secret := strings.TrimPrefix(v, "cpat_")
			for _, s := range []string{v, secret, domain.HashSecret(v)} {
				for _, text := range texts {
					if strings.Contains(text, s) {
						t.Fatalf("a log record holds a token value or a hash (%s...)", s[:6])
					}
				}
				if strings.Contains(spans, s) {
					t.Fatalf("a span holds a token value or a hash (%s...)", s[:6])
				}
			}
		}
	})
}

// I1: migration 0010 up and down on a database with data of 0009.
func TestIssue9MigrationIntegration(t *testing.T) {
	env := testserver.NewEnv(t)
	u, _ := env.PG.NewDatabase(t)
	pool, err := pgxpool.New(ctx, string(u))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrations(t, pool, 1, 9)
	const userID = "00000000-0000-4000-8000-0000000000aa"
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, name, status, created_at, updated_at) VALUES ($1, 'm@example.com', 'M', 'active', now(), now())`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at)
		VALUES ('00000000-0000-4000-8000-0000000000b1', $1, 'old', now(), now(), now() + interval '1 hour', now() + interval '1 day')`, userID); err != nil {
		t.Fatal(err)
	}
	applyMigrations(t, pool, 10, 10)
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'api_tokens'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("api_tokens after the up: %d, %v", n, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO api_tokens (id, token_hash, user_id, name, scope, created_at, expires_at)
		VALUES ('00000000-0000-4000-8000-0000000000c1', 'h', $1, 'n', 'demo:ticket:read', now(), now() + interval '1 day')`, userID); err != nil {
		t.Fatal(err)
	}
	// A name with 101 characters breaks the check.
	if _, err := pool.Exec(ctx, `INSERT INTO api_tokens (id, token_hash, user_id, name, scope, created_at, expires_at)
		VALUES ('00000000-0000-4000-8000-0000000000c2', 'h2', $1, repeat('a', 101), 'x', now(), now())`, userID); err == nil {
		t.Fatal("a name with 101 characters must fail")
	}
	// The old version of the service runs on the new schema.
	if _, err := pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE token_hash = 'old'`); err != nil {
		t.Fatal(err)
	}
	down, err := migrations.Files.ReadFile("0010_api_tokens.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'api_tokens'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("api_tokens after the down: %d, %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("users after the down: %d, %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("sessions after the down: %d, %v", n, err)
	}
}
