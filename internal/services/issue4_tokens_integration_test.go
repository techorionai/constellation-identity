//go:build integration

package services_test

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

// refreshState reads the revoke state of the family of a refresh token.
func (f *fixture) familyRevoked(sessionID string) (revoked, total int) {
	f.t.Helper()
	total = f.countWhere(`SELECT count(*) FROM refresh_token_families WHERE session_id = $1`, sessionID)
	revoked = f.countWhere(`SELECT count(*) FROM refresh_token_families WHERE session_id = $1 AND revoked_at IS NOT NULL`, sessionID)
	return revoked, total
}

func (f *fixture) refresh(clientID, token string) (testserver.Response, testserver.TokenResponse) {
	f.t.Helper()
	return f.a.TokenRequest(f.t, testserver.RefreshForm(clientID, token))
}

func TestIssue4RefreshIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h)
	admin := f.adminToken(adminScopes)
	userID := f.newUser(admin, "agent@example.com", userPass2, "demo:agent")
	f.newUser(admin, "agent2@example.com", userPass2, "demo:agent", "demo:admin")

	t.Run("I5_rotation_and_reuse", func(t *testing.T) {
		before := counterValue(t, "identity.refresh_token.reuse")
		first, web := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		resp, second := f.refresh("demo-ui", first.RefreshToken)
		if resp.StatusCode != http.StatusOK || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken || second.IDToken != "" {
			t.Fatalf("refresh: %d %+v", resp.StatusCode, second)
		}
		if second.Scope != "demo:ticket:read" {
			t.Fatalf("scope = %q", second.Scope)
		}
		// The old token is a reuse. The revoke stays in the database.
		if _, r := f.refresh("demo-ui", first.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("reuse: %+v", r)
		}
		sid := f.sessionID(web)
		if rev, total := f.familyRevoked(sid); rev != total || total != 1 {
			t.Fatalf("families revoked = %d of %d", rev, total)
		}
		if f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NOT NULL`, sid) != 1 {
			t.Fatal("the session must be revoked")
		}
		if _, r := f.refresh("demo-ui", second.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("the new token after the reuse: %+v", r)
		}
		if counterValue(t, "identity.refresh_token.reuse") != before+1 {
			t.Fatal("identity.refresh_token.reuse must rise by 1")
		}
		var warn bool
		for _, r := range f.a.logs.Records(t) {
			if r["event"] == "identity.refresh_token.reuse" && r["level"] == "WARN" && r["session_id"] == sid && r["family_id"] != nil && r["client_id"] == "demo-ui" {
				warn = true
			}
		}
		if !warn {
			t.Fatal("no warn record for the refresh reuse")
		}
	})

	t.Run("I5a_parallel_refresh", func(t *testing.T) {
		first, web := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		var wg sync.WaitGroup
		results := make([]testserver.TokenResponse, 2)
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, results[i] = f.refresh("demo-ui", first.RefreshToken)
			}()
		}
		wg.Wait()
		ok := 0
		for _, r := range results {
			if r.RefreshToken != "" {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("successful refreshes = %d, want 1", ok)
		}
		if rev, total := f.familyRevoked(f.sessionID(web)); rev != total {
			t.Fatalf("the family must be revoked after the reuse: %d of %d", rev, total)
		}
	})

	t.Run("I5b_role_change", func(t *testing.T) {
		tr, _ := f.login("agent2@example.com", userPass2, "demo-ui", demoRedirect, "openid offline_access demo:ticket:read demo:ticket:write")
		if !strings.Contains(tr.Scope, "demo:ticket:write") {
			t.Fatalf("scope = %q", tr.Scope)
		}
		_, users := f.api(admin, http.MethodGet, "/v1/users?pageSize=200", nil)
		var id string
		for _, it := range users["items"].([]any) {
			if it.(map[string]any)["email"] == "agent2@example.com" {
				id = it.(map[string]any)["id"].(string)
			}
		}
		if resp, _ := f.api(admin, http.MethodDelete, "/v1/users/"+id+"/roles/demo:admin", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove role: %d", resp.StatusCode)
		}
		resp, r := f.refresh("demo-ui", tr.RefreshToken)
		if resp.StatusCode != http.StatusOK || r.Scope != "demo:ticket:read" {
			t.Fatalf("scope after the role change: %d %+v", resp.StatusCode, r)
		}
		if resp, _ := f.api(admin, http.MethodDelete, "/v1/users/"+id+"/roles/demo:agent", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove role: %d", resp.StatusCode)
		}
		if _, r2 := f.refresh("demo-ui", r.RefreshToken); r2.Error != "invalid_grant" {
			t.Fatalf("refresh with no scope left: %+v", r2)
		}
		f.api(admin, http.MethodPut, "/v1/users/"+id+"/roles/demo:agent", nil)
	})

	t.Run("I5c_I5d_I5f_client_checks", func(t *testing.T) {
		// A client made by the API can be disabled.
		resp, m := f.api(admin, http.MethodPost, "/v1/clients", map[string]any{
			"type": "public", "app": "demo", "name": "Extra", "redirectUris": []string{"https://extra.example.com/cb"},
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create client: %d %v", resp.StatusCode, m)
		}
		cid := m["id"].(string)
		tr, web := f.login("agent@example.com", userPass2, cid, "https://extra.example.com/cb", demoScope)
		if resp, _ := f.api(admin, http.MethodPatch, "/v1/clients/"+cid, map[string]any{"disabled": true}); resp.StatusCode != http.StatusOK {
			t.Fatalf("disable: %d", resp.StatusCode)
		}
		if _, r := f.refresh(cid, tr.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("refresh of a disabled client: %+v", r)
		}
		f.api(admin, http.MethodPatch, "/v1/clients/"+cid, map[string]any{"disabled": false})
		if _, r := f.refresh(cid, tr.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("refresh after the enable: %+v", r)
		}
		if rev, total := f.familyRevoked(f.sessionID(web)); rev != total || total != 1 {
			t.Fatalf("families = %d of %d", rev, total)
		}

		// I5d: a wrong client ID does not use the token.
		tr, _ = f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		if _, r := f.refresh("loopback-ui", tr.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("wrong client: %+v", r)
		}
		resp2, ok := f.refresh("demo-ui", tr.RefreshToken)
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("right client after a wrong client: %+v", ok)
		}
		// I5f: a used token with a wrong client ID is a reuse.
		if _, r := f.refresh("loopback-ui", tr.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("reuse with a wrong client: %+v", r)
		}
		if _, r := f.refresh("demo-ui", ok.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("the new token must be revoked: %+v", r)
		}
	})

	t.Run("I6_I7_I7a_I23c_I23d_revoke", func(t *testing.T) {
		tr, web := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, "openid offline_access demo:ticket:read")
		// I6: an admin revokes the session.
		if resp, _ := f.api(admin, http.MethodDelete, "/v1/sessions/"+f.sessionID(web), nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke session: %d", resp.StatusCode)
		}
		if _, r := f.refresh("demo-ui", tr.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("refresh after the session revoke: %+v", r)
		}
		if resp, _ := f.api(admin, http.MethodDelete, "/v1/sessions/"+f.sessionID(web), nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("second revoke: %d", resp.StatusCode)
		}
		if resp, _ := f.api(admin, http.MethodDelete, "/v1/sessions/00000000-0000-4000-8000-000000000000", nil); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("revoke of an unknown session: %d", resp.StatusCode)
		}

		// I7: the revoke endpoint.
		tr, _ = f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, "openid offline_access demo:ticket:read")
		// I7a: another client cannot revoke the token.
		resp, b := f.a.Post(t, "/oauth/revoke", url.Values{"token": {tr.RefreshToken}, "client_id": {"loopback-ui"}}.Encode())
		if resp.StatusCode != http.StatusBadRequest || decode(t, b)["error"] != "unauthorized_client" {
			t.Fatalf("revoke by another client: %d %s", resp.StatusCode, b)
		}
		// I23c: a narrower scope applies to that access token only.
		resp2, narrow := f.a.TokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "client_id": {"demo-ui"}, "refresh_token": {tr.RefreshToken}, "scope": {"demo:ticket:read"}})
		if resp2.StatusCode != http.StatusOK || narrow.Scope != "demo:ticket:read" || narrow.IDToken != "" {
			t.Fatalf("narrow scope: %+v", narrow)
		}
		if _, wide := f.a.TokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "client_id": {"demo-ui"}, "refresh_token": {narrow.RefreshToken}, "scope": {"demo:ticket:write"}}); wide.Error != "invalid_scope" {
			t.Fatalf("wide scope: %+v", wide)
		}
		resp, b = f.a.Post(t, "/oauth/revoke", url.Values{"token": {narrow.RefreshToken}, "client_id": {"demo-ui"}, "token_type_hint": {"refresh_token"}}.Encode())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke: %d %s", resp.StatusCode, b)
		}
		if _, r := f.refresh("demo-ui", narrow.RefreshToken); r.Error != "invalid_grant" {
			t.Fatalf("refresh after the revoke: %+v", r)
		}
		for name, form := range map[string]url.Values{
			"unknown token": {"token": {"unknown"}, "client_id": {"demo-ui"}},
			"access token":  {"token": {tr.AccessToken}, "client_id": {"demo-ui"}},
		} {
			if resp, _ := f.a.Post(t, "/oauth/revoke", form.Encode()); resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: %d", name, resp.StatusCode)
			}
		}
		resp, b = f.a.Post(t, "/oauth/revoke", url.Values{"token": {"x"}, "client_id": {"demo-ui"}, "token_type_hint": {"other"}}.Encode())
		if resp.StatusCode != http.StatusBadRequest || decode(t, b)["error"] != "unsupported_token_type" {
			t.Fatalf("bad hint: %d %s", resp.StatusCode, b)
		}
		resp, _ = f.a.Post(t, "/oauth/revoke", url.Values{"token": {"x"}, "client_id": {"demo-ui"}, "client_secret": {"s"}}.Encode())
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("revoke with a secret: %d", resp.StatusCode)
		}
	})

	t.Run("I25_I25a_races", func(t *testing.T) {
		for i := 0; i < 8; i++ {
			tr, web := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				f.a.Post(t, "/oauth/revoke", url.Values{"token": {tr.RefreshToken}, "client_id": {"demo-ui"}}.Encode())
			}()
			var res testserver.TokenResponse
			go func() { defer wg.Done(); _, res = f.refresh("demo-ui", tr.RefreshToken) }()
			wg.Wait()
			if res.RefreshToken != "" {
				if _, r := f.refresh("demo-ui", res.RefreshToken); r.Error != "invalid_grant" {
					t.Fatalf("a token of the family is valid after the revoke: %+v", r)
				}
			}
			_ = web
		}
		for i := 0; i < 8; i++ {
			tr, web := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
			var wg sync.WaitGroup
			wg.Add(2)
			var res testserver.TokenResponse
			var logoutStatus int
			go func() {
				defer wg.Done()
				resp, _ := web.PostForm(t, "/logout", url.Values{})
				logoutStatus = resp.StatusCode
			}()
			go func() { defer wg.Done(); _, res = f.refresh("demo-ui", tr.RefreshToken) }()
			wg.Wait()
			if logoutStatus != http.StatusSeeOther {
				t.Fatalf("logout status = %d", logoutStatus)
			}
			if res.RefreshToken != "" {
				if _, r := f.refresh("demo-ui", res.RefreshToken); r.Error != "invalid_grant" {
					t.Fatalf("a token is valid after the logout: %+v", r)
				}
			}
		}
		for i := 0; i < 8; i++ {
			tr, _ := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
			var wg sync.WaitGroup
			wg.Add(2)
			var res testserver.TokenResponse
			var status int
			go func() {
				defer wg.Done()
				resp, _ := f.api(admin, http.MethodDelete, "/v1/users/"+userID+"/sessions", nil)
				status = resp.StatusCode
			}()
			go func() { defer wg.Done(); _, res = f.refresh("demo-ui", tr.RefreshToken) }()
			wg.Wait()
			if status != http.StatusNoContent {
				t.Fatalf("revoke all: %d", status)
			}
			if res.RefreshToken != "" {
				if _, r := f.refresh("demo-ui", res.RefreshToken); r.Error != "invalid_grant" {
					t.Fatalf("a token is valid after the revoke of all sessions: %+v", r)
				}
			}
		}
	})

	t.Run("I26a_parallel_code", func(t *testing.T) {
		for i := 0; i < 8; i++ {
			web := f.a.NewWeb()
			p := testserver.NewPKCE(t)
			code := codeOf(t, web.CodeFlow(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, nil), "agent@example.com", userPass2))
			var wg sync.WaitGroup
			results := make([]testserver.TokenResponse, 2)
			for j := range results {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, results[j] = f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, p.Verifier))
				}()
			}
			wg.Wait()
			ok := 0
			var winner testserver.TokenResponse
			for _, r := range results {
				if r.AccessToken != "" {
					ok++
					winner = r
				}
			}
			if ok != 1 {
				t.Fatalf("token sets = %d, want 1", ok)
			}
			sid := f.sessionID(web)
			revoked := f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NOT NULL`, sid) == 1
			if revoked {
				if _, r := f.refresh("demo-ui", winner.RefreshToken); r.Error != "invalid_grant" {
					t.Fatalf("state B: the refresh token of the winner works: %+v", r)
				}
			}
		}
	})

	t.Run("I26b_family_insert_checks_session", func(t *testing.T) {
		pool := f.a.Pool(t)
		repo := postgresRefresh(pool)
		for name, mutate := range map[string]string{
			"revoked":      `UPDATE sessions SET revoked_at = now() WHERE id = $1`,
			"idle expired": `UPDATE sessions SET idle_expires_at = now() - interval '1 minute' WHERE id = $1`,
			"expired":      `UPDATE sessions SET expires_at = now() - interval '1 minute' WHERE id = $1`,
			"valid":        `SELECT 1 WHERE $1::text <> ''`,
		} {
			_, web := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, "openid demo:ticket:read")
			sid := f.sessionID(web)
			if _, err := pool.Exec(ctx, mutate, sid); err != nil {
				t.Fatal(err)
			}
			fam := domain.RefreshFamily{ID: "00000000-0000-4000-8000-0000000000aa", SessionID: sid, ClientID: "demo-ui", UserID: userID, Scope: []string{"demo:ticket:read"}, CreatedAt: time.Now()}
			tok := domain.RefreshToken{Hash: "hash-" + name, FamilyID: fam.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
			inserted, err := repo.InsertFamilyIfSessionValid(ctx, fam, tok, time.Now())
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if inserted != (name == "valid") {
				t.Fatalf("%s: inserted = %v", name, inserted)
			}
			if inserted {
				if _, err := pool.Exec(ctx, `DELETE FROM refresh_token_families WHERE id = $1`, fam.ID); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
	// The test moves the clock far ahead, so it is the last one.
	// R13: a refresh with the OIDC scopes of the original grant is not an error.
	t.Run("refresh_with_oidc_scopes", func(t *testing.T) {
		tr, _ := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		form := testserver.RefreshForm("demo-ui", tr.RefreshToken)
		form.Set("scope", "openid offline_access demo:ticket:read")
		resp, r := f.a.TokenRequest(t, form)
		if resp.StatusCode != http.StatusOK || r.Scope != "demo:ticket:read" || r.RefreshToken == "" {
			t.Fatalf("refresh with OIDC scopes: %d %+v", resp.StatusCode, r)
		}
		// A scope that the grant did not have still gives invalid_scope.
		form = testserver.RefreshForm("demo-ui", r.RefreshToken)
		form.Set("scope", "profile")
		if _, r2 := f.a.TokenRequest(t, form); r2.Error != "invalid_scope" {
			t.Fatalf("refresh with profile: %+v", r2)
		}
	})

	t.Run("I5e_expiry", func(t *testing.T) {
		tr, _ := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		f.advance(11 * time.Hour)
		resp, r := f.refresh("demo-ui", tr.RefreshToken)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("refresh before the idle expiry: %+v", r)
		}
		// The refresh moved the idle expiry. The session lives past 12 hours from the login.
		f.advance(11 * time.Hour)
		resp, r2 := f.refresh("demo-ui", r.RefreshToken)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("refresh after the idle expiry moved: %+v", r2)
		}
		f.advance(13 * time.Hour)
		if _, r3 := f.refresh("demo-ui", r2.RefreshToken); r3.Error != "invalid_grant" {
			t.Fatalf("refresh after the idle expiry: %+v", r3)
		}
		tr, _ = f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		cur := tr.RefreshToken
		steps := 0
		for i := 0; i < 20; i++ {
			f.advance(11 * time.Hour)
			_, n := f.refresh("demo-ui", cur)
			if n.RefreshToken == "" {
				break
			}
			cur = n.RefreshToken
			steps++
		}
		// The session lives 168 hours. 15 steps of 11 hours are 165 hours.
		if steps != 15 {
			t.Fatalf("refresh steps before the absolute expiry = %d, want 15", steps)
		}
		f.advance(time.Hour)
		if _, r4 := f.refresh("demo-ui", cur); r4.Error != "invalid_grant" {
			t.Fatalf("refresh after the absolute expiry: %+v", r4)
		}
	})

	_ = pages.CookieName
}

// signingKeys makes the active signing key unavailable or available again. The
// key cache reloads every 100 ms, so the helper waits for 1 second.
func (f *fixture) signingKeys(available bool) {
	f.t.Helper()
	q := `UPDATE signing_keys SET state = 'retired', retired_at = now() WHERE state = 'active'`
	if available {
		q = `UPDATE signing_keys SET state = 'active', retired_at = NULL WHERE state = 'retired'`
	}
	if _, err := f.a.Pool(f.t).Exec(ctx, q); err != nil {
		f.t.Fatal(err)
	}
	time.Sleep(time.Second)
}

// R10: a signing fault must not use the refresh token or the code. The client
// can try again with the same value.
func TestIssue4SigningFaultIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h, testserver.WithKeyIntervals(time.Hour, 100*time.Millisecond))
	admin := f.adminToken(adminScopes)
	f.newUser(admin, "agent@example.com", userPass2, "demo:agent")

	t.Run("refresh", func(t *testing.T) {
		tr, web := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
		f.signingKeys(false)
		resp, r := f.refresh("demo-ui", tr.RefreshToken)
		f.signingKeys(true)
		if resp.StatusCode != http.StatusServiceUnavailable || r.Error != "temporarily_unavailable" || r.RefreshToken != "" {
			t.Fatalf("refresh with no signing key: %d %+v", resp.StatusCode, r)
		}
		resp, r = f.refresh("demo-ui", tr.RefreshToken)
		if resp.StatusCode != http.StatusOK || r.RefreshToken == "" {
			t.Fatalf("retry with the same token: %d %+v", resp.StatusCode, r)
		}
		if rev, total := f.familyRevoked(f.sessionID(web)); rev != 0 || total != 1 {
			t.Fatalf("families revoked = %d of %d", rev, total)
		}
	})

	t.Run("code", func(t *testing.T) {
		web := f.a.NewWeb()
		p := testserver.NewPKCE(t)
		code := codeOf(t, web.CodeFlow(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, nil), "agent@example.com", userPass2))
		f.signingKeys(false)
		resp, r := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, p.Verifier))
		f.signingKeys(true)
		if resp.StatusCode != http.StatusServiceUnavailable || r.Error != "temporarily_unavailable" {
			t.Fatalf("code with no signing key: %d %+v", resp.StatusCode, r)
		}
		if f.countWhere(`SELECT count(*) FROM refresh_token_families WHERE session_id = $1`, f.sessionID(web)) != 0 {
			t.Fatal("no family may exist after the fault")
		}
		resp, r = f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, p.Verifier))
		if resp.StatusCode != http.StatusOK || r.RefreshToken == "" {
			t.Fatalf("retry with the same code: %d %+v", resp.StatusCode, r)
		}
	})
}
