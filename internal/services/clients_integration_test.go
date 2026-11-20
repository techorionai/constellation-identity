//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/auth"
	"github.com/techorionai/constellation-platform-go/auth/jwt"
	"github.com/techorionai/constellation-platform-go/clients/identity"
	"github.com/techorionai/constellation-platform-go/manifest"

	"github.com/techorionai/constellation-identity/internal/adapters/postgres"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

// manifestJSON makes the body of a manifest publish. roles maps a role key to
// its permissions. The order of the roles follows roleOrder.
func manifestJSON(t *testing.T, app string, perms []string, roleOrder []string, roles map[string][]string) string {
	t.Helper()
	type perm struct {
		Key         string `json:"key"`
		Description string `json:"description"`
	}
	type role struct {
		Key         string   `json:"key"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	m := struct {
		App          string `json:"app"`
		Permissions  []perm `json:"permissions"`
		DefaultRoles []role `json:"defaultRoles"`
	}{App: app, Permissions: []perm{}, DefaultRoles: []role{}}
	for _, p := range perms {
		m.Permissions = append(m.Permissions, perm{Key: p, Description: "Permission " + p})
	}
	for _, k := range roleOrder {
		m.DefaultRoles = append(m.DefaultRoles, role{Key: k, Name: k, Description: "Role " + k, Permissions: roles[k]})
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var demoPerms = []string{"demo:ticket:read", "demo:ticket:write"}

func demoManifestJSON(t *testing.T) string {
	return manifestJSON(t, "demo", demoPerms, []string{"agent", "admin"}, map[string][]string{
		"agent": {"demo:ticket:read"},
		"admin": {"demo:ticket:read", "demo:ticket:write"},
	})
}

func token(t *testing.T, s *testserver.Server, c testserver.ServiceClient, audience string, scopes ...string) string {
	t.Helper()
	tok, err := s.TokenSource(t, c).Token(ctx, audience, scopes...)
	if err != nil {
		t.Fatalf("token for %s: %v", c.ID, err)
	}
	return tok
}

func decode(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("body %q: %v", body, err)
	}
	return m
}

func publish(t *testing.T, s *testserver.Server, tok, app, body string) (testserver.Response, map[string]any) {
	t.Helper()
	resp, b := s.Do(t, http.MethodPut, "/v1/permission-manifests/"+app, tok, body)
	return resp, decode(t, b)
}

func oauthError(t *testing.T, s *testserver.Server, form url.Values, wantStatus int, wantCode string) {
	t.Helper()
	resp, b := s.PostToken(t, form)
	m := decode(t, b)
	if resp.StatusCode != wantStatus || m["error"] != wantCode {
		t.Fatalf("status = %d, body = %s, want %d %s", resp.StatusCode, b, wantStatus, wantCode)
	}
}

func jwtConfig(s *testserver.Server, audience string) jwt.Config {
	return jwt.Config{
		Issuer: s.Config.Issuer, Audience: audience,
		JWKSURL: s.PublicURL + "/.well-known/jwks.json", AllowInsecureHTTP: true,
	}
}

func TestIssue2Integration(t *testing.T) {
	env := testserver.NewEnv(t)

	// I1: a service client gets a token with auth/clientcred. The issuer is
	// localhost and the client calls 127.0.0.1, so the two values differ.
	t.Run("I1_service_token", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		s := env.Start(t, testserver.WithClients(t, demo))
		tok := token(t, s, demo, "identity", "identity:manifest:publish")
		v, err := jwt.New(jwtConfig(s, "identity"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := v.Verify(ctx, tok)
		if err != nil {
			t.Fatal(err)
		}
		if p.ID != "demo" || p.Type != auth.PrincipalService || p.ClientID != "demo" ||
			!slices.Equal(p.Scopes, []string{"identity:manifest:publish"}) {
			t.Fatalf("principal = %+v", p)
		}
	})

	// I2 and I2a: publish, list, get, and the roles.
	t.Run("I2_publish_list_get", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		ops := testserver.NewServiceClient(t, "ops", "ops", "identity:admin")
		s := env.Start(t, testserver.WithClients(t, demo, ops))
		resp, m := publish(t, s, token(t, s, demo, "identity", "identity:manifest:publish"), "demo", demoManifestJSON(t))
		if resp.StatusCode != http.StatusOK || m["version"] != float64(1) {
			t.Fatalf("publish: status = %d, body = %v", resp.StatusCode, m)
		}

		read := token(t, s, ops, "identity", "identity:role:read")
		_, b := s.Do(t, http.MethodGet, "/v1/permission-manifests", read, "")
		var page struct {
			Items []struct {
				Manifest struct {
					App string `json:"app"`
				} `json:"manifest"`
				Version int `json:"version"`
			} `json:"items"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			t.Fatal(err)
		}
		apps := map[string]int{}
		for _, it := range page.Items {
			apps[it.Manifest.App] = it.Version
		}
		if apps["demo"] != 1 || apps["identity"] != 1 || len(apps) != 2 {
			t.Fatalf("manifests = %v", apps)
		}

		resp, b = s.Do(t, http.MethodGet, "/v1/permission-manifests/demo", read, "")
		got := decode(t, b)
		if resp.StatusCode != http.StatusOK || got["version"] != float64(1) {
			t.Fatalf("get manifest: %d %s", resp.StatusCode, b)
		}

		_, b = s.Do(t, http.MethodGet, "/v1/roles?app=demo", read, "")
		var roles struct {
			Items []struct {
				Ref         string   `json:"ref"`
				Permissions []string `json:"permissions"`
			} `json:"items"`
			NextPageToken *string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(b, &roles); err != nil {
			t.Fatal(err)
		}
		if len(roles.Items) != 2 || roles.Items[0].Ref != "demo:admin" || roles.Items[1].Ref != "demo:agent" || roles.NextPageToken != nil {
			t.Fatalf("roles = %s", b)
		}
		resp, b = s.Do(t, http.MethodGet, "/v1/roles/demo:agent", read, "")
		role := decode(t, b)
		if resp.StatusCode != http.StatusOK || role["ref"] != "demo:agent" || role["key"] != "agent" || role["app"] != "demo" {
			t.Fatalf("get role: %d %s", resp.StatusCode, b)
		}

		// I2a: an unknown role, and paging.
		resp, b = s.Do(t, http.MethodGet, "/v1/roles/demo:unknown", read, "")
		if resp.StatusCode != http.StatusNotFound || decode(t, b)["code"] != "not_found" {
			t.Fatalf("unknown role: %d %s", resp.StatusCode, b)
		}
		_, b = s.Do(t, http.MethodGet, "/v1/roles?app=demo&pageSize=1", read, "")
		first := decode(t, b)
		items := first["items"].([]any)
		next, _ := first["nextPageToken"].(string)
		if len(items) != 1 || next == "" || items[0].(map[string]any)["ref"] != "demo:admin" {
			t.Fatalf("first page = %s", b)
		}
		_, b = s.Do(t, http.MethodGet, "/v1/roles?app=demo&pageSize=1&pageToken="+url.QueryEscape(next), read, "")
		second := decode(t, b)
		items = second["items"].([]any)
		if len(items) != 1 || items[0].(map[string]any)["ref"] != "demo:agent" || second["nextPageToken"] != nil {
			t.Fatalf("second page = %s", b)
		}
		resp, _ = s.Do(t, http.MethodGet, "/v1/roles?pageSize=0", read, "")
		// The contract has minimum 1 for pageSize.
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("pageSize=0: status = %d", resp.StatusCode)
		}
		resp, _ = s.Do(t, http.MethodGet, "/v1/roles?pageToken=%21%21", read, "")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad page token: status = %d", resp.StatusCode)
		}
	})

	// I3: the same manifest again, in another order, changes nothing.
	t.Run("I3_same_manifest", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		s := env.Start(t, testserver.WithClients(t, demo))
		tok := token(t, s, demo, "identity", "identity:manifest:publish")
		if resp, m := publish(t, s, tok, "demo", demoManifestJSON(t)); resp.StatusCode != 200 || m["version"] != float64(1) {
			t.Fatalf("first publish: %d %v", resp.StatusCode, m)
		}
		var stamp time.Time
		if err := s.Pool(t).QueryRow(ctx, `SELECT published_at FROM apps WHERE key = 'demo'`).Scan(&stamp); err != nil {
			t.Fatal(err)
		}
		reordered := manifestJSON(t, "demo", []string{"demo:ticket:write", "demo:ticket:read"}, []string{"admin", "agent"}, map[string][]string{
			"agent": {"demo:ticket:read"},
			"admin": {"demo:ticket:write", "demo:ticket:read"},
		})
		if resp, m := publish(t, s, tok, "demo", reordered); resp.StatusCode != 200 || m["version"] != float64(1) {
			t.Fatalf("second publish: %d %v", resp.StatusCode, m)
		}
		var stamp2 time.Time
		var version int
		if err := s.Pool(t).QueryRow(ctx, `SELECT published_at, manifest_version FROM apps WHERE key = 'demo'`).Scan(&stamp2, &version); err != nil {
			t.Fatal(err)
		}
		if !stamp.Equal(stamp2) || version != 1 {
			t.Fatalf("the tables changed: %s %s version %d", stamp, stamp2, version)
		}
		if n := count(t, s, `SELECT count(*) FROM roles WHERE app = 'demo'`); n != 2 {
			t.Fatalf("roles = %d", n)
		}
	})

	// I4: a role with an assignment is deleted, then comes back. U11: the
	// assignment is pending in between.
	t.Run("I4_deleted_role_is_pending", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		helpdesk := testserver.NewServiceClient(t, "helpdesk", "helpdesk", "demo:agent")
		s := env.Start(t, testserver.WithClients(t, demo, helpdesk))
		demoTok := token(t, s, demo, "identity", "identity:manifest:publish")
		assignments := func() []domain.RoleAssignment {
			a, err := postgres.NewClientRoles(s.Pool(t)).Assignments(ctx, "helpdesk")
			if err != nil {
				t.Fatal(err)
			}
			return a
		}
		wantRead := func(status int, code string) {
			t.Helper()
			form := testserver.TokenForm(s.Assertion(t, helpdesk, nil), "demo", "demo:ticket:read")
			if status == 200 {
				resp, b := s.PostToken(t, form)
				if resp.StatusCode != 200 {
					t.Fatalf("token request: %d %s", resp.StatusCode, b)
				}
				return
			}
			oauthError(t, s, form, status, code)
		}

		// The role does not exist yet. The assignment is pending.
		if a := assignments(); len(a) != 1 || !a[0].Pending || a[0].Role.String() != "demo:agent" || a[0].Source != domain.AssignmentConfig {
			t.Fatalf("assignments before the publish = %+v", a)
		}
		if resp, m := publish(t, s, demoTok, "demo", demoManifestJSON(t)); resp.StatusCode != 200 || m["version"] != float64(1) {
			t.Fatalf("publish v1: %d %v", resp.StatusCode, m)
		}
		if a := assignments(); len(a) != 1 || a[0].Pending {
			t.Fatalf("assignments at v1 = %+v", a)
		}
		wantRead(200, "")

		without := manifestJSON(t, "demo", demoPerms, []string{"admin"}, map[string][]string{"admin": demoPerms})
		if resp, m := publish(t, s, demoTok, "demo", without); resp.StatusCode != 200 || m["version"] != float64(2) {
			t.Fatalf("publish v2: %d %v", resp.StatusCode, m)
		}
		if n := count(t, s, `SELECT count(*) FROM client_roles WHERE client_id = 'helpdesk'`); n != 1 {
			t.Fatalf("the assignment row was deleted: %d rows", n)
		}
		if a := assignments(); len(a) != 1 || !a[0].Pending {
			t.Fatalf("assignments at v2 = %+v", a)
		}
		wantRead(400, "invalid_scope")

		if resp, m := publish(t, s, demoTok, "demo", demoManifestJSON(t)); resp.StatusCode != 200 || m["version"] != float64(3) {
			t.Fatalf("publish v3: %d %v", resp.StatusCode, m)
		}
		if a := assignments(); len(a) != 1 || a[0].Pending {
			t.Fatalf("assignments at v3 = %+v", a)
		}
		wantRead(200, "")
	})

	// I4a: two parallel publishes of different manifests.
	t.Run("I4a_parallel_publish", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		s := env.Start(t, testserver.WithClients(t, demo))
		tok := token(t, s, demo, "identity", "identity:manifest:publish")
		if resp, _ := publish(t, s, tok, "demo", demoManifestJSON(t)); resp.StatusCode != 200 {
			t.Fatalf("baseline: %d", resp.StatusCode)
		}
		a := manifestJSON(t, "demo", demoPerms, []string{"agent"}, map[string][]string{"agent": {"demo:ticket:read"}})
		b := manifestJSON(t, "demo", demoPerms, []string{"agent"}, map[string][]string{"agent": demoPerms})
		versions := make([]float64, 2)
		statuses := make([]int, 2)
		var wg sync.WaitGroup
		for i, body := range []string{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, b := s.Do(t, http.MethodPut, "/v1/permission-manifests/demo", tok, body)
				statuses[i] = resp.StatusCode
				var m map[string]any
				_ = json.Unmarshal(b, &m)
				versions[i], _ = m["version"].(float64)
			}()
		}
		wg.Wait()
		slices.Sort(versions)
		if statuses[0] != 200 || statuses[1] != 200 || versions[0] != 2 || versions[1] != 3 {
			t.Fatalf("statuses = %v, versions = %v", statuses, versions)
		}
	})

	// I5 and I5a: a client publishes for another app, and for identity.
	t.Run("I5_app_mismatch", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		s := env.Start(t, testserver.WithClients(t, demo))
		tok := token(t, s, demo, "identity", "identity:manifest:publish")
		other := manifestJSON(t, "other", []string{"other:thing:read"}, nil, nil)
		resp, m := publish(t, s, tok, "other", other)
		if resp.StatusCode != http.StatusUnprocessableEntity || m["code"] != "manifest_app_mismatch" {
			t.Fatalf("other app: %d %v", resp.StatusCode, m)
		}
		// The path is demo and the body is for another app.
		resp, m = publish(t, s, tok, "demo", other)
		if resp.StatusCode != http.StatusUnprocessableEntity || m["code"] != "manifest_app_mismatch" {
			t.Fatalf("body of another app: %d %v", resp.StatusCode, m)
		}

		// I5a: the app identity.
		before := count(t, s, `SELECT count(*) FROM role_permissions WHERE app = 'identity'`)
		forged := manifestJSON(t, "identity", []string{"identity:admin"}, []string{"admin", "service"}, map[string][]string{
			"admin": {"identity:admin"}, "service": {"identity:admin"},
		})
		resp, m = publish(t, s, tok, "identity", forged)
		if resp.StatusCode != http.StatusUnprocessableEntity || m["code"] != "manifest_app_mismatch" {
			t.Fatalf("identity: %d %v", resp.StatusCode, m)
		}
		if after := count(t, s, `SELECT count(*) FROM role_permissions WHERE app = 'identity'`); after != before {
			t.Fatalf("the identity roles changed: %d to %d", before, after)
		}
		if n := count(t, s, `SELECT count(*) FROM role_permissions WHERE app = 'identity' AND role = 'service' AND permission = 'identity:admin'`); n != 0 {
			t.Fatal("the role service has identity:admin")
		}
	})

	// The checks of the keys give the contract codes and all errors.
	t.Run("manifest_checks", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		s := env.Start(t, testserver.WithClients(t, demo))
		tok := token(t, s, demo, "identity", "identity:manifest:publish")
		bad := manifestJSON(t, "demo", []string{"email:message:send", "demo:ticket:read"}, []string{"agent"},
			map[string][]string{"agent": {"demo:ticket:read", "demo:ticket:delete"}})
		resp, m := publish(t, s, tok, "demo", bad)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, body = %v", resp.StatusCode, m)
		}
		errs, _ := m["errors"].([]any)
		var codes []string
		for _, e := range errs {
			codes = append(codes, e.(map[string]any)["code"].(string))
		}
		slices.Sort(codes)
		if !slices.Equal(codes, []string{"permission_app_mismatch", "role_permission_unknown"}) || m["code"] != "permission_app_mismatch" {
			t.Fatalf("problem = %v", m)
		}
		if n := count(t, s, `SELECT count(*) FROM apps WHERE key = 'demo'`); n != 0 {
			t.Fatal("a bad manifest was stored")
		}
	})

	// I6 and I12: a token without the scope.
	t.Run("I6_I12_missing_scope", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		ops := testserver.NewServiceClient(t, "ops", "ops", "identity:admin")
		s := env.Start(t, testserver.WithClients(t, demo, ops))
		readOnly := token(t, s, ops, "identity", "identity:role:read")
		resp, m := publish(t, s, readOnly, "demo", demoManifestJSON(t))
		if resp.StatusCode != http.StatusForbidden || !slices.Equal(toStrings(m["missingScopes"]), []string{"identity:manifest:publish"}) {
			t.Fatalf("publish without the scope: %d %v", resp.StatusCode, m)
		}
		resp, _ = publish(t, s, "", "demo", demoManifestJSON(t))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("publish without a token: %d", resp.StatusCode)
		}

		// I12: a publish token calls GET /v1/roles.
		pub := token(t, s, demo, "identity", "identity:manifest:publish")
		resp, b := s.Do(t, http.MethodGet, "/v1/roles", pub, "")
		m = decode(t, b)
		if resp.StatusCode != http.StatusForbidden || !slices.Equal(toStrings(m["missingScopes"]), []string{"identity:role:read"}) {
			t.Fatalf("I12: %d %s", resp.StatusCode, b)
		}
		// A token for another audience does not pass.
		if resp, _ := s.Do(t, http.MethodGet, "/v1/roles", "not-a-token", ""); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bad token: %d", resp.StatusCode)
		}
	})

	// I7 and I7a: an assertion works one time.
	t.Run("I7_replay", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		s := env.Start(t, testserver.WithClients(t, demo))
		a := s.Assertion(t, demo, nil)
		form := testserver.TokenForm(a, "identity", "identity:manifest:publish")
		if resp, b := s.PostToken(t, form); resp.StatusCode != 200 {
			t.Fatalf("first use: %d %s", resp.StatusCode, b)
		} else if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
			t.Fatalf("headers = %v", resp.Header)
		}
		oauthError(t, s, form, 401, "invalid_client")

		// I7a: an expired assertion, two times.
		old := s.Assertion(t, demo, func(c, _ map[string]any) {
			c["iat"] = time.Now().Add(-10 * time.Minute).Unix()
			c["exp"] = time.Now().Add(-5 * time.Minute).Unix()
		})
		oldForm := testserver.TokenForm(old, "identity", "identity:manifest:publish")
		oauthError(t, s, oldForm, 401, "invalid_client")
		oauthError(t, s, oldForm, 401, "invalid_client")
	})

	// I8, I9, and I9a.
	t.Run("I8_I9_client_errors", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		other := testserver.NewServiceClient(t, "other", "other")
		off := testserver.NewServiceClient(t, "off", "off")
		s := env.Start(t, testserver.WithClients(t, demo, other, off))
		if resp, _ := publish(t, s, token(t, s, demo, "identity", "identity:manifest:publish"), "demo", demoManifestJSON(t)); resp.StatusCode != 200 {
			t.Fatal("publish")
		}
		// I8: the sub is demo, and the key is the key of another client.
		forged := testserver.SignAssertion(t, other.Key, demo.KID, map[string]any{
			"iss": "demo", "sub": "demo", "aud": s.Config.Issuer, "jti": "forged-1",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
		}, nil)
		oauthError(t, s, testserver.TokenForm(forged, "demo", "demo:ticket:read"), 401, "invalid_client")

		// I9: a disabled client.
		if _, err := s.Pool(t).Exec(ctx, `UPDATE clients SET disabled = true WHERE id = 'off'`); err != nil {
			t.Fatal(err)
		}
		oauthError(t, s, testserver.TokenForm(s.Assertion(t, off, nil), "identity", "identity:manifest:publish"), 401, "invalid_client")

		// I9a: the audience.
		for _, aud := range []string{"", "nope", "emptyapp", "No:pe"} {
			oauthError(t, s, testserver.TokenForm(s.Assertion(t, demo, nil), aud, "demo:ticket:read"), 400, "invalid_target")
		}

		// A scope that the client does not have, and no scope.
		oauthError(t, s, testserver.TokenForm(s.Assertion(t, demo, nil), "demo", "demo:ticket:read"), 400, "invalid_scope")
		oauthError(t, s, testserver.TokenForm(s.Assertion(t, demo, nil), "identity", ""), 400, "invalid_scope")

		// A client secret next to the assertion, and another grant.
		form := testserver.TokenForm(s.Assertion(t, demo, nil), "identity", "identity:manifest:publish")
		form.Set("client_secret", "x")
		oauthError(t, s, form, 400, "invalid_request")
		form = testserver.TokenForm(s.Assertion(t, demo, nil), "identity", "identity:manifest:publish")
		form.Set("grant_type", "authorization_code")
		oauthError(t, s, form, 400, "unsupported_grant_type")
	})

	// I10: a role of an app that did not publish yet.
	t.Run("I10_pending_before_publish", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		helpdesk := testserver.NewServiceClient(t, "helpdesk", "helpdesk", "demo:agent")
		s := env.Start(t, testserver.WithClients(t, demo, helpdesk))
		oauthError(t, s, testserver.TokenForm(s.Assertion(t, helpdesk, nil), "demo", "demo:ticket:read"), 400, "invalid_target")
		if resp, _ := publish(t, s, token(t, s, demo, "identity", "identity:manifest:publish"), "demo", demoManifestJSON(t)); resp.StatusCode != 200 {
			t.Fatal("publish")
		}
		if tok := token(t, s, helpdesk, "demo", "demo:ticket:read"); tok == "" {
			t.Fatal("no token")
		}
		// The role agent does not give the write scope.
		oauthError(t, s, testserver.TokenForm(s.Assertion(t, helpdesk, nil), "demo", "demo:ticket:write"), 400, "invalid_scope")
	})

	// A restart with a changed clients file replaces the config roles.
	t.Run("clients_file_roles_replaced", func(t *testing.T) {
		helpdesk := testserver.NewServiceClient(t, "helpdesk", "helpdesk", "demo:agent", "demo:admin")
		s := env.Start(t, testserver.WithClients(t, helpdesk))
		helpdesk.Roles = []string{"demo:agent"}
		s2 := env.Start(t, testserver.WithDB(s.DB), testserver.WithMasterKey(s.Config.Secrets.MasterKey.Reveal(), s.Config.Secrets.MasterKeyID),
			testserver.WithClients(t, helpdesk))
		a, err := postgres.NewClientRoles(s2.Pool(t)).Assignments(ctx, "helpdesk")
		if err != nil {
			t.Fatal(err)
		}
		if len(a) != 1 || a[0].Role.String() != "demo:agent" {
			t.Fatalf("assignments = %+v", a)
		}
	})

	// The identity manifest exists after the start.
	t.Run("identity_manifest_published", func(t *testing.T) {
		s := env.Start(t)
		if n := count(t, s, `SELECT count(*) FROM role_permissions WHERE app = 'identity' AND role = 'admin' AND permission = 'identity:admin'`); n != 1 {
			t.Fatalf("admin has identity:admin: %d", n)
		}
		if n := count(t, s, `SELECT count(*) FROM role_permissions WHERE app = 'identity' AND permission = 'identity:admin'`); n != 1 {
			t.Fatalf("holders of identity:admin: %d", n)
		}
	})

	// I-E2E: the exit test of milestone M1.
	t.Run("I-E2E", func(t *testing.T) {
		demo := testserver.NewServiceClient(t, "demo", "demo")
		helpdesk := testserver.NewServiceClient(t, "helpdesk", "helpdesk", "demo:agent")
		s := env.Start(t, testserver.WithClients(t, demo, helpdesk))

		// (2) The client demo publishes its manifest with platform-go.
		idc, err := identity.New(identity.Config{URL: s.PublicURL, Timeout: 10 * time.Second, AllowInsecureHTTP: true},
			s.TokenSource(t, demo), []string{"identity:manifest:publish"})
		if err != nil {
			t.Fatal(err)
		}
		pub := manifest.NewPublisher(identity.NewManifestRegistry(idc), manifest.PermissionManifest{
			App: "demo",
			Permissions: []manifest.PermissionDefinition{
				{Key: "demo:ticket:read", Description: "Read tickets."},
				{Key: "demo:ticket:write", Description: "Write tickets."},
			},
			DefaultRoles: []manifest.RoleDefinition{
				{Key: "agent", Name: "Agent", Description: "Reads tickets.", Permissions: []string{"demo:ticket:read"}},
			},
		})
		pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := pub.Run(pctx); err != nil {
			t.Fatalf("publish: %v", err)
		}

		// (3) The client helpdesk gets a token for demo.
		tok, err := s.TokenSource(t, helpdesk).Token(ctx, "demo", "demo:ticket:read")
		if err != nil {
			t.Fatal(err)
		}

		// (4) and (5) Two servers with auth.Middleware.
		newServer := func(audience string) *httptest.Server {
			v, err := jwt.New(jwtConfig(s, audience))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(v.Close)
			mux := http.NewServeMux()
			ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			mux.Handle("GET /tickets", auth.RequireScopes("demo:ticket:read")(ok))
			mux.Handle("POST /tickets", auth.RequireScopes("demo:ticket:write")(ok))
			srv := httptest.NewServer(auth.Middleware(v)(mux))
			t.Cleanup(srv.Close)
			return srv
		}
		type result struct {
			status int
			header http.Header
		}
		call := func(srv *httptest.Server, method string) (result, map[string]any) {
			req, err := http.NewRequestWithContext(ctx, method, srv.URL+"/tickets", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var m map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&m)
			return result{status: resp.StatusCode, header: resp.Header}, m
		}
		a, b := newServer("demo"), newServer("other")

		if res, _ := call(a, http.MethodGet); res.status != http.StatusOK {
			t.Fatalf("GET on server A: %d", res.status)
		}
		res, m := call(a, http.MethodPost)
		if res.status != http.StatusForbidden || !slices.Equal(toStrings(m["missingScopes"]), []string{"demo:ticket:write"}) {
			t.Fatalf("POST on server A: %d %v", res.status, m)
		}
		res, _ = call(b, http.MethodGet)
		if res.status != http.StatusUnauthorized || res.header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
			t.Fatalf("GET on server B: %d %v", res.status, res.header)
		}
	})
}

// I11: Valkey stops. The token request gives 503 and no token. The test has its
// own containers, because it stops Valkey.
func TestIssue2Integration_I11_ValkeyDown(t *testing.T) {
	env := testserver.NewEnv(t)
	demo := testserver.NewServiceClient(t, "demo", "demo")
	s := env.Start(t, testserver.WithClients(t, demo))
	form := testserver.TokenForm(s.Assertion(t, demo, nil), "identity", "identity:manifest:publish")
	if err := env.VK.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	resp, b := s.PostToken(t, form)
	m := decode(t, b)
	if resp.StatusCode != http.StatusServiceUnavailable || m["error"] != "temporarily_unavailable" || m["access_token"] != nil {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, b)
	}
}

func toStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, i := range items {
		s, _ := i.(string)
		out = append(out, s)
	}
	return out
}
