//go:build integration

package services_test

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

func code(m map[string]any) string {
	s, _ := m["code"].(string)
	return s
}

func items(m map[string]any) []map[string]any {
	var out []map[string]any
	list, _ := m["items"].([]any)
	for _, it := range list {
		out = append(out, it.(map[string]any))
	}
	return out
}

func TestIssue4AdminIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h)
	admin := f.adminToken(adminScopes)

	// I9, I10, I10a: a user from creation to disable.
	t.Run("I9_I10_user_lifecycle", func(t *testing.T) {
		resp, m := f.api(admin, http.MethodPost, "/v1/users", map[string]string{"email": "life@example.com", "name": "Life"})
		if resp.StatusCode != http.StatusCreated || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("create: %d %v", resp.StatusCode, m)
		}
		id := m["user"].(map[string]any)["id"].(string)
		// I13l: a duplicate email.
		resp, m2 := f.api(admin, http.MethodPost, "/v1/users", map[string]string{"email": "life@example.com", "name": "Again"})
		if resp.StatusCode != http.StatusConflict || code(m2) != "email_taken" {
			t.Fatalf("duplicate: %d %v", resp.StatusCode, m2)
		}
		// A new invite replaces the old one for an invited user.
		resp, m3 := f.api(admin, http.MethodPost, "/v1/users/"+id+"/invites", nil)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("invite: %d %v", resp.StatusCode, m3)
		}
		invite := m3["url"].(string)
		web := f.a.NewWeb()
		resp, _ = web.PostForm(t, "/invite", url.Values{"token": {testserver.TokenOf(t, invite)}, "password": {userPass2}, "password2": {userPass2}})
		status(t, resp, http.StatusSeeOther, "accept")
		// I11c: an invite for an active user.
		resp, m4 := f.api(admin, http.MethodPost, "/v1/users/"+id+"/invites", nil)
		if resp.StatusCode != http.StatusConflict || code(m4) != "user_not_invited" {
			t.Fatalf("invite for an active user: %d %v", resp.StatusCode, m4)
		}
		if resp, m := f.api(admin, http.MethodPut, "/v1/users/"+id+"/roles/demo:agent", nil); resp.StatusCode != http.StatusOK || m["pending"] != false || m["source"] != "api" {
			t.Fatalf("assign: %d %v", resp.StatusCode, m)
		}
		tr, _ := f.login("life@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		_, claims := testserver.JWTClaims(t, tr.AccessToken)
		if claims["scope"] != "demo:ticket:read" {
			t.Fatalf("scope = %v", claims["scope"])
		}
		// A new unused invite token exists for a user with a pending invite: I10 deletes it.
		resp, m5 := f.api(admin, http.MethodPost, "/v1/users", map[string]string{"email": "invited@example.com", "name": "Invited"})
		invitedID := m5["user"].(map[string]any)["id"].(string)
		if resp.StatusCode != http.StatusCreated || f.countWhere(`SELECT count(*) FROM one_time_tokens WHERE user_id = $1 AND used_at IS NULL`, invitedID) != 1 {
			t.Fatalf("invited user: %d", resp.StatusCode)
		}
		// I10: disable.
		if resp, m := f.api(admin, http.MethodPatch, "/v1/users/"+invitedID, map[string]any{"disabled": true}); resp.StatusCode != http.StatusOK || m["status"] != "disabled" {
			t.Fatalf("disable invited: %d %v", resp.StatusCode, m)
		}
		if f.countWhere(`SELECT count(*) FROM one_time_tokens WHERE user_id = $1 AND used_at IS NULL`, invitedID) != 0 {
			t.Fatal("the unused invite tokens must be deleted")
		}
		// An enabled user with no password is invited again (U8).
		if _, m := f.api(admin, http.MethodPatch, "/v1/users/"+invitedID, map[string]any{"disabled": false}); m["status"] != "invited" {
			t.Fatalf("enable with no password: %v", m)
		}
		if resp, _ := f.api(admin, http.MethodPatch, "/v1/users/"+invitedID, map[string]any{"disabled": true}); resp.StatusCode != http.StatusOK {
			t.Fatal("disable")
		}
		if resp, m := f.api(admin, http.MethodPost, "/v1/users/"+invitedID+"/invites", nil); resp.StatusCode != http.StatusConflict || code(m) != "user_disabled" {
			t.Fatalf("invite for a disabled user: %d %v", resp.StatusCode, m)
		}

		resp, m6 := f.api(admin, http.MethodPatch, "/v1/users/"+id, map[string]any{"disabled": true})
		if resp.StatusCode != http.StatusOK || m6["status"] != "disabled" {
			t.Fatalf("disable: %d %v", resp.StatusCode, m6)
		}
		if f.countWhere(`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, id) != 0 ||
			f.countWhere(`SELECT count(*) FROM refresh_token_families WHERE user_id = $1 AND revoked_at IS NULL`, id) != 0 {
			t.Fatal("the sessions and the families must be revoked")
		}
		if _, r := f.refresh("demo-ui", tr.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("refresh of a disabled user: %+v", r)
		}
		w := f.a.NewWeb()
		resp, _ = w.PostForm(t, "/login", url.Values{"email": {"life@example.com"}, "password": {userPass2}})
		status(t, resp, http.StatusUnauthorized, "login of a disabled user")
		// I10a: enable.
		if _, m := f.api(admin, http.MethodPatch, "/v1/users/"+id, map[string]any{"disabled": false}); m["status"] != "active" {
			t.Fatalf("enable: %v", m)
		}
		// I13g, I13h, I13j: name, me, get.
		if _, m := f.api(admin, http.MethodPatch, "/v1/users/"+id, map[string]any{"name": "New Name"}); m["name"] != "New Name" {
			t.Fatalf("name: %v", m)
		}
		if resp, m := f.api(admin, http.MethodGet, "/v1/users/"+id, nil); resp.StatusCode != http.StatusOK || m["email"] != "life@example.com" {
			t.Fatalf("get: %d", resp.StatusCode)
		}
		if resp, _ := f.api(admin, http.MethodGet, "/v1/users/00000000-0000-4000-8000-000000000000", nil); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unknown user: %d", resp.StatusCode)
		}
		if resp, m := f.api(admin, http.MethodGet, "/v1/me", nil); resp.StatusCode != http.StatusOK || m["email"] != "admin@example.com" {
			t.Fatalf("me: %d %v", resp.StatusCode, m)
		}
		svc := f.serviceToken()
		if resp, _ := f.api(svc, http.MethodGet, "/v1/me", nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("me with a service token: %d", resp.StatusCode)
		}
	})

	// I11, I11a, I11b: scopes.
	t.Run("I11_scopes", func(t *testing.T) {
		low := f.adminToken("identity:user:read")
		for _, op := range []struct{ method, path string }{
			{http.MethodPost, "/v1/users"}, {http.MethodPatch, "/v1/users/x"}, {http.MethodPost, "/v1/users/x/invites"},
			{http.MethodGet, "/v1/users/x/roles"}, {http.MethodPut, "/v1/users/x/roles/demo:agent"}, {http.MethodDelete, "/v1/users/x/roles/demo:agent"},
			{http.MethodGet, "/v1/users/x/sessions"}, {http.MethodDelete, "/v1/users/x/sessions"}, {http.MethodDelete, "/v1/sessions/x"},
			{http.MethodGet, "/v1/clients"}, {http.MethodPost, "/v1/clients"}, {http.MethodGet, "/v1/clients/x"}, {http.MethodPatch, "/v1/clients/x"},
			{http.MethodPost, "/v1/clients/x/keys"}, {http.MethodDelete, "/v1/clients/x/keys/k"},
			{http.MethodGet, "/v1/clients/x/roles"}, {http.MethodPut, "/v1/clients/x/roles/demo:agent"}, {http.MethodDelete, "/v1/clients/x/roles/demo:agent"},
		} {
			resp, m := f.api(low, op.method, op.path, nil)
			if resp.StatusCode != http.StatusForbidden || m["missingScopes"] == nil {
				t.Fatalf("%s %s: %d %v", op.method, op.path, resp.StatusCode, m)
			}
		}
		// I11a: identity:client:write alone is not enough.
		write := f.adminToken("identity:client:write identity:client:read")
		jwk := testserver.NewServiceClient(t, "k1", "x").JWK(t)
		jwk["kid"] = "k1"
		for _, op := range []struct {
			method, path string
			body         any
		}{
			{http.MethodPost, "/v1/clients", map[string]any{"type": "service", "app": "svc", "name": "S"}},
			{http.MethodPatch, "/v1/clients/x", map[string]any{"name": "N"}},
			{http.MethodPost, "/v1/clients/x/keys", jwk},
			{http.MethodDelete, "/v1/clients/x/keys/k1", nil},
		} {
			resp, m := f.api(write, op.method, op.path, op.body)
			if resp.StatusCode != http.StatusForbidden || !slices.Contains(toStrings(m["missingScopes"]), "identity:admin") {
				t.Fatalf("%s %s: %d %v", op.method, op.path, resp.StatusCode, m)
			}
		}
		if f.countWhere(`SELECT count(*) FROM clients WHERE source = 'api'`) != 0 {
			t.Fatal("the refused calls must not make a client")
		}
		// I13o: identity:role:assign gives every role.
		id := f.newUser(admin, "assign@example.com", userPass2)
		assign := f.adminToken("identity:role:assign")
		if resp, _ := f.api(assign, http.MethodPut, "/v1/users/"+id+"/roles/identity:admin", nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("assign identity:admin: %d", resp.StatusCode)
		}
	})

	// I11b, I13b to I13f, I13i to I13m: clients.
	t.Run("I13_clients", func(t *testing.T) {
		tok := admin
		svc := testserver.NewServiceClient(t, "k", "x")
		jwk := svc.JWK(t)
		jwk["kid"] = "key-1"
		resp, m := f.api(tok, http.MethodPost, "/v1/clients", map[string]any{"type": "service", "app": "worker", "name": "Worker", "jwk": jwk})
		if resp.StatusCode != http.StatusCreated || m["source"] != "api" {
			t.Fatalf("create service client: %d %v", resp.StatusCode, m)
		}
		cid := m["id"].(string)
		// A reserved app.
		if resp, m := f.api(tok, http.MethodPost, "/v1/clients", map[string]any{"type": "service", "app": "identity", "name": "S"}); resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "app_reserved" {
			t.Fatalf("app_reserved: %d %v", resp.StatusCode, m)
		}
		// I13a: a private member.
		bad := map[string]any{}
		for k, v := range jwk {
			bad[k] = v
		}
		bad["kid"], bad["d"] = "key-2", "AAAA"
		if resp, m := f.api(tok, http.MethodPost, "/v1/clients/"+cid+"/keys", bad); resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "invalid_jwk" {
			t.Fatalf("invalid_jwk: %d %v", resp.StatusCode, m)
		}
		// I13: add a key, get a token with it, delete the key.
		second := testserver.NewServiceClient(t, "second", "worker")
		jwk2 := second.JWK(t)
		jwk2["kid"] = "second-key"
		if resp, m := f.api(tok, http.MethodPost, "/v1/clients/"+cid+"/keys", jwk2); resp.StatusCode != http.StatusCreated {
			t.Fatalf("add key: %d %v", resp.StatusCode, m)
		}
		if resp, m := f.api(tok, http.MethodPut, "/v1/clients/"+cid+"/roles/demo:agent", nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("assign: %d %v", resp.StatusCode, m)
		}
		apiClient := testserver.ServiceClient{ID: cid, App: "worker", KID: "second-key", Key: second.Key}
		if _, err := f.a.TokenSource(t, apiClient).Token(ctx, "demo", "demo:ticket:read"); err != nil {
			t.Fatalf("token with the key that the API added: %v", err)
		}
		if resp, _ := f.api(tok, http.MethodDelete, "/v1/clients/"+cid+"/keys/second-key", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete key: %d", resp.StatusCode)
		}
		if _, err := f.a.TokenSource(t, apiClient).Token(ctx, "demo", "demo:ticket:read"); err == nil {
			t.Fatal("the deleted key must not work")
		}
		// I13e: client roles.
		resp, m = f.api(tok, http.MethodGet, "/v1/clients/"+cid+"/roles", nil)
		var refs []string
		for _, it := range items(m) {
			refs = append(refs, it["role"].(string))
		}
		if resp.StatusCode != http.StatusOK || !slices.Contains(refs, "identity:service") || !slices.Contains(refs, "demo:agent") {
			t.Fatalf("client roles: %d %v", resp.StatusCode, refs)
		}
		if resp, _ := f.api(tok, http.MethodDelete, "/v1/clients/"+cid+"/roles/demo:agent", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove client role: %d", resp.StatusCode)
		}
		// I13c: an unknown role.
		if resp, m := f.api(tok, http.MethodPut, "/v1/clients/"+cid+"/roles/demo:unknown", nil); resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "role_unknown" {
			t.Fatalf("client role_unknown: %d %v", resp.StatusCode, m)
		}
		uid := f.newUser(tok, "roles@example.com", userPass2)
		if resp, m := f.api(tok, http.MethodPut, "/v1/users/"+uid+"/roles/demo:unknown", nil); resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "role_unknown" {
			t.Fatalf("user role_unknown: %d %v", resp.StatusCode, m)
		}
		// I13b: a client of the clients file.
		if resp, m := f.api(tok, http.MethodPatch, "/v1/clients/demo", map[string]any{"name": "X"}); resp.StatusCode != http.StatusConflict || code(m) != "client_managed_by_config" {
			t.Fatalf("patch config client: %d %v", resp.StatusCode, m)
		}
		if resp, m := f.api(tok, http.MethodPost, "/v1/clients/demo/keys", jwk2); resp.StatusCode != http.StatusConflict || code(m) != "client_managed_by_config" {
			t.Fatalf("key of a config client: %d %v", resp.StatusCode, m)
		}
		if resp, m := f.api(tok, http.MethodPut, "/v1/clients/demo/roles/demo:admin", nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("extra role by API for a config client: %d %v", resp.StatusCode, m)
		}
		// I11b: a body with app.
		if resp, _ := f.api(tok, http.MethodPatch, "/v1/clients/"+cid, map[string]any{"app": "other"}); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("app in the body: %d", resp.StatusCode)
		}
		if _, m := f.api(tok, http.MethodGet, "/v1/clients/"+cid, nil); m["app"] != "worker" {
			t.Fatalf("app = %v", m["app"])
		}
		// A type change.
		if resp, m := f.api(tok, http.MethodPatch, "/v1/clients/"+cid, map[string]any{"type": "public"}); resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "client_type_immutable" {
			t.Fatalf("type change: %d %v", resp.StatusCode, m)
		}
		// I13d, I13m: redirect URIs.
		resp, pm := f.api(tok, http.MethodPost, "/v1/clients", map[string]any{"type": "public", "app": "demo", "name": "Pub", "redirectUris": []string{"https://p.example.com/cb", "http://127.0.0.1/cb"}})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create public: %d %v", resp.StatusCode, pm)
		}
		pid := pm["id"].(string)
		if resp, m := f.api(tok, http.MethodPost, "/v1/clients", map[string]any{"type": "public", "app": "demo", "name": "Bad", "redirectUris": []string{"https://a.example.com/cb#x"}}); resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "invalid_redirect_uri" {
			t.Fatalf("invalid_redirect_uri: %d %v", resp.StatusCode, m)
		}
		if resp, m := f.api(tok, http.MethodPatch, "/v1/clients/"+pid, map[string]any{"redirectUris": []string{"https://a.example.com/cb#x"}}); resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "invalid_redirect_uri" {
			t.Fatalf("patch invalid_redirect_uri: %d %v", resp.StatusCode, m)
		}
		if _, m := f.api(tok, http.MethodGet, "/v1/clients/"+pid, nil); len(m["redirectUris"].([]any)) != 2 {
			t.Fatalf("the client must not change: %v", m)
		}
		// Keys and roles of a public client.
		if resp, m := f.api(tok, http.MethodPost, "/v1/clients/"+pid+"/keys", jwk2); resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "client_type_unsupported" {
			t.Fatalf("key of a public client: %d %v", resp.StatusCode, m)
		}
		if resp, m := f.api(tok, http.MethodGet, "/v1/clients/"+pid+"/roles", nil); resp.StatusCode != http.StatusUnprocessableEntity || code(m) != "client_type_unsupported" {
			t.Fatalf("roles of a public client: %d %v", resp.StatusCode, m)
		}
		// I13j: get, list, unknown.
		if resp, _ := f.api(tok, http.MethodGet, "/v1/clients/nobody", nil); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unknown client: %d", resp.StatusCode)
		}
		if resp, m := f.api(tok, http.MethodGet, "/v1/clients?pageSize=200", nil); resp.StatusCode != http.StatusOK || len(items(m)) < 6 {
			t.Fatalf("list clients: %d", resp.StatusCode)
		}
	})

	// I12, I12a, I12b, I12c: the last admin.
	t.Run("I12_last_admin", func(t *testing.T) {
		fx := newFixture(t, h)
		tok := fx.adminToken(adminScopes)
		_, me := fx.api(tok, http.MethodGet, "/v1/me", nil)
		adminID := me["id"].(string)
		if resp, m := fx.api(tok, http.MethodPatch, "/v1/users/"+adminID, map[string]any{"disabled": true}); resp.StatusCode != http.StatusConflict || code(m) != "last_admin" {
			t.Fatalf("disable the last admin: %d %v", resp.StatusCode, m)
		}
		if resp, m := fx.api(tok, http.MethodDelete, "/v1/users/"+adminID+"/roles/identity:admin", nil); resp.StatusCode != http.StatusConflict || code(m) != "last_admin" {
			t.Fatalf("remove the role of the last admin: %d %v", resp.StatusCode, m)
		}
		if fx.countWhere(`SELECT count(*) FROM users WHERE status = 'active'`) != 1 {
			t.Fatal("the admin must stay active")
		}
		// Two admins that disable each other in parallel: exactly one passes.
		other := fx.newUser(tok, "admin2@example.com", userPass2, "identity:admin")
		var wg sync.WaitGroup
		codes := make([]int, 2)
		targets := []string{adminID, other}
		for i := range targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, _ := fx.api(tok, http.MethodPatch, "/v1/users/"+targets[i], map[string]any{"disabled": true})
				codes[i] = resp.StatusCode
			}()
		}
		wg.Wait()
		ok, conflict := 0, 0
		for _, c := range codes {
			switch c {
			case http.StatusOK:
				ok++
			case http.StatusConflict:
				conflict++
			}
		}
		if ok != 1 || conflict != 1 {
			t.Fatalf("parallel disable: %v", codes)
		}
		if fx.countWhere(`SELECT count(*) FROM users u JOIN user_roles r ON r.user_id = u.id WHERE u.status = 'active' AND r.role = 'admin' AND r.app = 'identity'`) != 1 {
			t.Fatal("exactly one active admin must stay")
		}
	})

	t.Run("I12b_I12c_roles_race_and_pending", func(t *testing.T) {
		fx := newFixture(t, h)
		tok := fx.adminToken(adminScopes)
		_, me := fx.api(tok, http.MethodGet, "/v1/me", nil)
		adminID := me["id"].(string)
		other := fx.newUser(tok, "admin2@example.com", userPass2, "identity:admin")
		var wg sync.WaitGroup
		codes := make([]int, 2)
		targets := []string{adminID, other}
		for i := range targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, _ := fx.api(tok, http.MethodDelete, "/v1/users/"+targets[i]+"/roles/identity:admin", nil)
				codes[i] = resp.StatusCode
			}()
		}
		wg.Wait()
		if !slices.Contains(codes, http.StatusNoContent) || !slices.Contains(codes, http.StatusConflict) {
			t.Fatalf("parallel role delete: %v", codes)
		}
		// I12c: a pending assignment does not count.
		fx2 := newFixture(t, h)
		tok2 := fx2.adminToken(adminScopes)
		_, me2 := fx2.api(tok2, http.MethodGet, "/v1/me", nil)
		pid := fx2.newUser(tok2, "pending@example.com", userPass2)
		if _, err := fx2.a.Pool(t).Exec(ctx, `INSERT INTO user_roles (user_id, app, role, source) VALUES ($1, 'ghost', 'admin', 'api')`, pid); err != nil {
			t.Fatal(err)
		}
		if resp, m := fx2.api(tok2, http.MethodPatch, "/v1/users/"+me2["id"].(string), map[string]any{"disabled": true}); resp.StatusCode != http.StatusConflict || code(m) != "last_admin" {
			t.Fatalf("disable with a pending admin role elsewhere: %d %v", resp.StatusCode, m)
		}
		// I13n: a pending assignment in the list.
		_, list := fx2.api(tok2, http.MethodGet, "/v1/users/"+pid+"/roles", nil)
		// The list has the pending role and the implicit role identity:user (issue 9).
		if got := items(list); len(got) != 2 || got[0]["pending"] != true || got[1]["role"] != "identity:user" || got[1]["pending"] != false {
			t.Fatalf("pending list: %v", list)
		}
	})

	// I13f: sessions of a user.
	t.Run("I13f_sessions", func(t *testing.T) {
		id := f.newUser(admin, "sess@example.com", userPass2, "demo:agent")
		f.login("sess@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		f.login("sess@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		_, m := f.api(admin, http.MethodGet, "/v1/users/"+id+"/sessions", nil)
		// The sessions of the invite accept and of the two logins.
		if len(items(m)) != 3 {
			t.Fatalf("sessions = %v", m)
		}
		if resp, _ := f.api(admin, http.MethodDelete, "/v1/users/"+id+"/sessions", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke all: %d", resp.StatusCode)
		}
		_, m = f.api(admin, http.MethodGet, "/v1/users/"+id+"/sessions", nil)
		if len(items(m)) != 0 {
			t.Fatalf("sessions after the revoke = %v", m)
		}
		if resp, _ := f.api(admin, http.MethodDelete, "/v1/users/00000000-0000-4000-8000-000000000000/sessions", nil); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("revoke all of an unknown user: %d", resp.StatusCode)
		}
	})

	// I22 to I22c: pagination.
	t.Run("I22_pagination", func(t *testing.T) {
		fx := newFixture(t, h)
		tok := fx.adminToken(adminScopes)
		for i := 0; i < 119; i++ {
			// Users 45 to 55 have the same creation time.
			if i < 44 || i > 54 {
				fx.advance(time.Millisecond)
			}
			resp, m := fx.api(tok, http.MethodPost, "/v1/users", map[string]string{"email": fmt.Sprintf("u%03d@example.com", i), "name": "U"})
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("create %d: %d %v", i, resp.StatusCode, m)
			}
		}
		seen := map[string]bool{}
		var sizes []int
		token := ""
		for page := 0; page < 5; page++ {
			path := "/v1/users?pageSize=50"
			if token != "" {
				path += "&pageToken=" + url.QueryEscape(token)
			}
			resp, m := fx.api(tok, http.MethodGet, path, nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("page %d: %d %v", page, resp.StatusCode, m)
			}
			sizes = append(sizes, len(items(m)))
			for _, it := range items(m) {
				id := it["id"].(string)
				if seen[id] {
					t.Fatalf("duplicate item %s", id)
				}
				seen[id] = true
			}
			next, _ := m["nextPageToken"].(string)
			if next == "" {
				break
			}
			token = next
		}
		if !slices.Equal(sizes, []int{50, 50, 20}) || len(seen) != 120 {
			t.Fatalf("pages = %v, items = %d", sizes, len(seen))
		}
		// I22a, I22b: bad tokens and sizes.
		for _, path := range []string{"/v1/users?pageToken=!!", "/v1/users?pageToken=" + url.QueryEscape("e30"), "/v1/users?pageSize=0", "/v1/users?pageSize=201",
			"/v1/users?pageToken=" + url.QueryEscape("WyJ4IiwieSJd")} {
			if resp, m := fx.api(tok, http.MethodGet, path, nil); resp.StatusCode != http.StatusBadRequest || code(m) != "invalid_request" {
				t.Fatalf("%s: %d %v", path, resp.StatusCode, m)
			}
		}
		// I22c: the role lists.
		uid := fx.newUser(tok, "rl@example.com", userPass2, "demo:agent", "demo:admin", "extra:viewer", "extra:editor", "identity:service")
		cl := testserver.NewServiceClient(t, "rl", "x")
		jwk := cl.JWK(t)
		jwk["kid"] = "rl-1"
		_, cm := fx.api(tok, http.MethodPost, "/v1/clients", map[string]any{"type": "service", "app": "svcrl", "name": "RL", "jwk": jwk})
		cid := cm["id"].(string)
		for _, r := range []string{"demo:agent", "demo:admin", "extra:viewer", "extra:editor"} {
			fx.api(tok, http.MethodPut, "/v1/clients/"+cid+"/roles/"+r, nil)
		}
		for _, base := range []string{"/v1/users/" + uid + "/roles", "/v1/clients/" + cid + "/roles"} {
			var got []string
			var sizes []int
			token := ""
			for page := 0; page < 5; page++ {
				path := base + "?pageSize=2"
				if token != "" {
					path += "&pageToken=" + url.QueryEscape(token)
				}
				_, m := fx.api(tok, http.MethodGet, path, nil)
				sizes = append(sizes, len(items(m)))
				for _, it := range items(m) {
					got = append(got, it["role"].(string))
				}
				next, _ := m["nextPageToken"].(string)
				if next == "" {
					break
				}
				token = next
			}
			want := []string{"demo:admin", "demo:agent", "extra:editor", "extra:viewer", "identity:service"}
			wantSizes := []int{2, 2, 1}
			if strings.Contains(base, "/users/") {
				// The list of a user has the implicit role identity:user (issue 9).
				want = []string{"demo:admin", "demo:agent", "extra:editor", "extra:viewer", "identity:service", "identity:user"}
				wantSizes = []int{2, 2, 2}
			}
			if !slices.Equal(got, want) || !slices.Equal(sizes, wantSizes) {
				t.Fatalf("%s: roles = %v, sizes = %v", base, got, sizes)
			}
		}
	})

	// I13i: the clients file with a bad public client.
	t.Run("I13i_bad_clients_file", func(t *testing.T) {
		bad := testserver.PublicClient{ID: "badui", App: "demo", RedirectURIs: []string{"http://example.com/cb"}}
		_, err := h.env.TryStart(t, testserver.WithPublicClients(t, []testserver.PublicClient{bad}))
		if err == nil || !strings.Contains(err.Error(), "badui") {
			t.Fatalf("start error = %v", err)
		}
	})
	_ = pages.CookieName
}
