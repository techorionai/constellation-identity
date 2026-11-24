//go:build integration

package services_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/techorionai/constellation-platform-go/auth"
	"github.com/techorionai/constellation-platform-go/auth/jwt"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/migrations"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

const (
	agentAdminScopes = adminScopes + " identity:agent:read identity:agent:write"
	extraRead        = "extra:item:read"
	extraWrite       = "extra:item:write"
)

// exchangeFixture is a server where the client demo can use the token exchange
// grant. The public client demo-ui and the service client demo are of the app
// demo. The apps extra has roles viewer (read) and editor (read and write).
type exchangeFixture struct {
	*fixture
	admin string
	h     *harness
}

func newExchangeFixture(t *testing.T, h *harness, f *fixture) *exchangeFixture {
	t.Helper()
	x := &exchangeFixture{fixture: f, admin: f.adminToken(agentAdminScopes), h: h}
	return x
}

func (x *exchangeFixture) grantExchange(clientID string) {
	x.t.Helper()
	resp, m := x.api(x.admin, http.MethodPut, "/v1/clients/"+clientID+"/roles/identity:admin", nil)
	if resp.StatusCode != http.StatusOK {
		x.t.Fatalf("grant exchange to %s: %d %v", clientID, resp.StatusCode, m)
	}
}

func (x *exchangeFixture) newAgent(name, clientID string, roles ...string) string {
	x.t.Helper()
	resp, m := x.api(x.admin, http.MethodPost, "/v1/agents", map[string]string{"name": name, "clientId": clientID})
	if resp.StatusCode != http.StatusCreated {
		x.t.Fatalf("create agent: %d %v", resp.StatusCode, m)
	}
	id, _ := m["id"].(string)
	for _, r := range roles {
		if resp, m := x.api(x.admin, http.MethodPut, "/v1/agents/"+id+"/roles/"+r, nil); resp.StatusCode != http.StatusOK {
			x.t.Fatalf("assign %s: %d %v", r, resp.StatusCode, m)
		}
	}
	return id
}

// subjectFor makes an active user and logs it in with the public client of the
// app demo. The token is a valid subject token for the client demo.
func (x *exchangeFixture) subjectFor(name string, roles ...string) (userID, token string) {
	x.t.Helper()
	email := name + "@example.com"
	userID = x.newUser(x.admin, email, userPassword, append([]string{"demo:agent"}, roles...)...)
	tr, _ := x.login(email, userPassword, "demo-ui", demoRedirect, "openid demo:ticket:read")
	x.a.ledger.add(&x.a.ledger.exchange, tr.AccessToken)
	return userID, tr.AccessToken
}

func (x *exchangeFixture) exchange(c testserver.ServiceClient, req auth.ExchangeRequest) (string, error) {
	x.t.Helper()
	tok, err := x.a.TokenSource(x.t, c).Exchange(ctx, req)
	x.a.ledger.add(&x.a.ledger.exchange, req.SubjectToken)
	if tok != "" {
		x.a.ledger.add(&x.a.ledger.exchange, tok)
	}
	return tok, err
}

// verifier makes the verifier of a service for the audience app.
func (x *exchangeFixture) verifier(aud string) *jwt.Verifier {
	x.t.Helper()
	v, err := jwt.New(jwt.Config{
		Issuer: x.a.Config.Issuer, Audience: aud, JWKSURL: x.a.PublicURL + "/.well-known/jwks.json",
		RefreshInterval: time.Minute, MinRefetchInterval: time.Second, AllowInsecureHTTP: true, HTTPTimeout: 5 * time.Second,
	})
	if err != nil {
		x.t.Fatal(err)
	}
	x.t.Cleanup(v.Close)
	return v
}

func oauthCode(t *testing.T, err error) string {
	t.Helper()
	var oe *auth.OAuthError
	if !errors.As(err, &oe) {
		t.Fatalf("error = %v, want an *auth.OAuthError", err)
	}
	if errors.Is(err, auth.ErrTokenUnavailable) {
		t.Fatalf("error = %v, must not be ErrTokenUnavailable", err)
	}
	return oe.Code
}

func wantOAuth(t *testing.T, what string, err error, code string) {
	t.Helper()
	if got := oauthCode(t, err); got != code {
		t.Fatalf("%s: code = %s, want %s (%v)", what, got, code, err)
	}
}

func TestIssue10Integration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h)
	x := newExchangeFixture(t, h, f)
	demo, extra := f.serviceClient, f.extraClient

	// I11: a service client without identity:token:exchange. This test runs before
	// the grants, and the check comes before the check of the other parameters.
	t.Run("I11_no_permission", func(t *testing.T) {
		_, subject := x.subjectFor("i11", "extra:editor")
		_, err := x.exchange(extra, auth.ExchangeRequest{SubjectToken: subject, Audience: "demo", Scopes: []string{"demo:ticket:read"}})
		wantOAuth(t, "client without the permission", err, "unauthorized_client")
		// The raw request with missing parameters gives the same code.
		form := testserver.TokenForm(f.a.Assertion(t, extra, nil), "demo", "demo:ticket:read")
		form.Set("grant_type", domain.GrantTypeTokenExchange)
		resp, body := f.a.PostToken(t, form)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "unauthorized_client") {
			t.Fatalf("missing parameters: %d %s", resp.StatusCode, body)
		}
	})
	x.grantExchange("demo")
	x.grantExchange("extra")

	// I2: the admin operations.
	t.Run("I2_agent_operations", func(t *testing.T) {
		resp, m := x.api(x.admin, http.MethodPost, "/v1/agents", map[string]string{"name": "  Planner  ", "clientId": "demo"})
		if resp.StatusCode != http.StatusCreated || m["name"] != "Planner" || m["clientId"] != "demo" || m["enabled"] != true ||
			m["createdAt"] == nil || m["updatedAt"] == nil {
			t.Fatalf("create: %d %v", resp.StatusCode, m)
		}
		id := m["id"].(string)
		resp, m = x.api(x.admin, http.MethodPut, "/v1/agents/"+id+"/roles/extra:viewer", nil)
		if resp.StatusCode != http.StatusOK || m["role"] != "extra:viewer" || m["source"] != "api" || m["pending"] != false {
			t.Fatalf("assign: %d %v", resp.StatusCode, m)
		}
		if resp, _ = x.api(x.admin, http.MethodPut, "/v1/agents/"+id+"/roles/extra:viewer", nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("assign again: %d", resp.StatusCode)
		}
		resp, m = x.api(x.admin, http.MethodGet, "/v1/agents/"+id+"/roles", nil)
		if resp.StatusCode != http.StatusOK || len(items(m)) != 1 || items(m)[0]["role"] != "extra:viewer" {
			t.Fatalf("roles: %d %v", resp.StatusCode, m)
		}
		resp, m = x.api(x.admin, http.MethodGet, "/v1/agents/"+id, nil)
		if resp.StatusCode != http.StatusOK || m["id"] != id {
			t.Fatalf("get: %d %v", resp.StatusCode, m)
		}
		resp, m = x.api(x.admin, http.MethodPatch, "/v1/agents/"+id, map[string]any{"name": "Planner 2", "enabled": false})
		if resp.StatusCode != http.StatusOK || m["name"] != "Planner 2" || m["enabled"] != false {
			t.Fatalf("update: %d %v", resp.StatusCode, m)
		}
		resp, m = x.api(x.admin, http.MethodPatch, "/v1/agents/"+id, map[string]any{})
		if resp.StatusCode != http.StatusOK || m["name"] != "Planner 2" {
			t.Fatalf("empty update: %d %v", resp.StatusCode, m)
		}
		resp, m = x.api(x.admin, http.MethodGet, "/v1/agents", nil)
		if resp.StatusCode != http.StatusOK || !slices.ContainsFunc(items(m), func(a map[string]any) bool { return a["id"] == id }) {
			t.Fatalf("list: %d %v", resp.StatusCode, m)
		}
		if resp, _ = x.api(x.admin, http.MethodDelete, "/v1/agents/"+id+"/roles/extra:viewer", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove: %d", resp.StatusCode)
		}
		if resp, _ = x.api(x.admin, http.MethodDelete, "/v1/agents/"+id+"/roles/extra:viewer", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove a missing role: %d", resp.StatusCode)
		}
		// One change record for each change, with the name of the operation.
		ops := map[string]bool{}
		for _, r := range f.a.logs.Records(t) {
			if r["event"] == "identity.admin.change" && r["target_id"] == id {
				ops[fmt.Sprint(r["operation"])] = true
			}
		}
		for _, op := range []string{"Agents_create", "Agents_update", "AgentRoles_assign", "AgentRoles_remove"} {
			if !ops[op] {
				t.Fatalf("no log record for %s: %v", op, ops)
			}
		}
	})

	// I2a: the errors and the scopes of the operations.
	t.Run("I2a_errors", func(t *testing.T) {
		a := x.newAgent("Errors", "demo")
		unknown := "00000000-0000-4000-8000-0000000000a1"
		for name, c := range map[string]struct {
			method, path string
			body         any
			status       int
			code         string
		}{
			"name taken":          {http.MethodPost, "/v1/agents", map[string]string{"name": "Errors", "clientId": "demo"}, 409, "agent_name_taken"},
			"client not found":    {http.MethodPost, "/v1/agents", map[string]string{"name": "E2", "clientId": "nobody"}, 422, "client_not_found"},
			"client not service":  {http.MethodPost, "/v1/agents", map[string]string{"name": "E3", "clientId": "demo-ui"}, 422, "client_not_service"},
			"bad name":            {http.MethodPost, "/v1/agents", map[string]string{"name": "   ", "clientId": "demo"}, 400, "invalid_request"},
			"get unknown":         {http.MethodGet, "/v1/agents/" + unknown, nil, 404, "agent_not_found"},
			"get bad id":          {http.MethodGet, "/v1/agents/x", nil, 404, "agent_not_found"},
			"update unknown":      {http.MethodPatch, "/v1/agents/" + unknown, map[string]any{"name": "N"}, 404, "agent_not_found"},
			"update bad id":       {http.MethodPatch, "/v1/agents/x", map[string]any{"name": "N"}, 404, "agent_not_found"},
			"update name taken":   {http.MethodPatch, "/v1/agents/" + a, map[string]any{"name": "Planner 2"}, 409, "agent_name_taken"},
			"update bad name":     {http.MethodPatch, "/v1/agents/" + a, map[string]any{"name": ""}, 400, "invalid_request"},
			"roles unknown":       {http.MethodGet, "/v1/agents/" + unknown + "/roles", nil, 404, "agent_not_found"},
			"roles bad id":        {http.MethodGet, "/v1/agents/x/roles", nil, 404, "agent_not_found"},
			"assign unknown":      {http.MethodPut, "/v1/agents/" + unknown + "/roles/extra:viewer", nil, 404, "agent_not_found"},
			"assign bad id":       {http.MethodPut, "/v1/agents/x/roles/extra:viewer", nil, 404, "agent_not_found"},
			"assign unknown role": {http.MethodPut, "/v1/agents/" + a + "/roles/extra:nothing", nil, 422, "role_unknown"},
			"agent first":         {http.MethodPut, "/v1/agents/" + unknown + "/roles/extra:nothing", nil, 404, "agent_not_found"},
			"remove unknown":      {http.MethodDelete, "/v1/agents/" + unknown + "/roles/extra:viewer", nil, 404, "agent_not_found"},
			"remove bad id":       {http.MethodDelete, "/v1/agents/x/roles/extra:viewer", nil, 404, "agent_not_found"},
			"bad page size":       {http.MethodGet, "/v1/agents?pageSize=0", nil, 400, "invalid_request"},
			"bad page token":      {http.MethodGet, "/v1/agents?pageToken=zzz", nil, 400, "invalid_request"},
		} {
			resp, m := x.api(x.admin, c.method, c.path, c.body)
			if resp.StatusCode != c.status || code(m) != c.code {
				t.Errorf("%s: %d %v, want %d %s", name, resp.StatusCode, m, c.status, c.code)
			}
		}
		// The scopes of the contract. The admin login gives only the scopes that are asked for.
		readOnly := x.adminToken("identity:agent:read")
		writeOnly := x.adminToken("identity:agent:write")
		assignOnly := x.adminToken("identity:role:assign")
		roleRead := x.adminToken("identity:role:read")
		for name, c := range map[string]struct {
			token, method, path string
			body                any
			status              int
		}{
			"create with read":         {readOnly, http.MethodPost, "/v1/agents", map[string]string{"name": "S1", "clientId": "demo"}, 403},
			"create write, no admin":   {writeOnly, http.MethodPost, "/v1/agents", map[string]string{"name": "S2", "clientId": "demo"}, 403},
			"list with write":          {writeOnly, http.MethodGet, "/v1/agents", nil, 403},
			"get with write":           {writeOnly, http.MethodGet, "/v1/agents/" + a, nil, 403},
			"update with read":         {readOnly, http.MethodPatch, "/v1/agents/" + a, map[string]any{"enabled": true}, 403},
			"update write, no admin":   {writeOnly, http.MethodPatch, "/v1/agents/" + a, map[string]any{"enabled": true}, 403},
			"roles list with read":     {readOnly, http.MethodGet, "/v1/agents/" + a + "/roles", nil, 403},
			"roles list with roleRead": {roleRead, http.MethodGet, "/v1/agents/" + a + "/roles", nil, 200},
			"assign with role read":    {roleRead, http.MethodPut, "/v1/agents/" + a + "/roles/extra:viewer", nil, 403},
			"assign role:assign only":  {assignOnly, http.MethodPut, "/v1/agents/" + a + "/roles/extra:viewer", nil, 200},
			"remove with role read":    {roleRead, http.MethodDelete, "/v1/agents/" + a + "/roles/extra:viewer", nil, 403},
			"remove role:assign only":  {assignOnly, http.MethodDelete, "/v1/agents/" + a + "/roles/extra:viewer", nil, 204},
			"list with read":           {readOnly, http.MethodGet, "/v1/agents", nil, 200},
			"get with read":            {readOnly, http.MethodGet, "/v1/agents/" + a, nil, 200},
			"no token":                 {"", http.MethodGet, "/v1/agents", nil, 401},
		} {
			if resp, m := x.api(c.token, c.method, c.path, c.body); resp.StatusCode != c.status {
				t.Errorf("%s: %d %v, want %d", name, resp.StatusCode, m, c.status)
			}
		}
	})

	// I2b: two parallel creates with the same name.
	t.Run("I2b_parallel_names", func(t *testing.T) {
		var wg sync.WaitGroup
		statuses := make([]int, 2)
		codes := make([]string, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, m := x.api(x.admin, http.MethodPost, "/v1/agents", map[string]string{"name": "Parallel", "clientId": "demo"})
				statuses[i], codes[i] = resp.StatusCode, code(m)
			}()
		}
		wg.Wait()
		slices.Sort(statuses)
		if statuses[0] != 201 || statuses[1] != 409 || (codes[0] != "agent_name_taken" && codes[1] != "agent_name_taken") {
			t.Fatalf("statuses %v, codes %v", statuses, codes)
		}
		if n := x.countWhere(`SELECT count(*) FROM agents WHERE name = 'Parallel'`); n != 1 {
			t.Fatalf("agents named Parallel = %d", n)
		}
	})

	// I2c: pages.
	t.Run("I2c_pages", func(t *testing.T) {
		for _, n := range []string{"Page 1", "Page 2", "Page 3"} {
			x.newAgent(n, "demo")
		}
		total := x.countWhere(`SELECT count(*) FROM agents`)
		var seen []string
		token := ""
		for pages := 0; pages <= total; pages++ {
			path := "/v1/agents?pageSize=1"
			if token != "" {
				path += "&pageToken=" + url.QueryEscape(token)
			}
			resp, m := x.api(x.admin, http.MethodGet, path, nil)
			if resp.StatusCode != http.StatusOK || len(items(m)) != 1 {
				t.Fatalf("page %d: %d %v", pages, resp.StatusCode, m)
			}
			seen = append(seen, items(m)[0]["id"].(string))
			token, _ = m["nextPageToken"].(string)
			if token == "" {
				break
			}
		}
		if len(seen) != total {
			t.Fatalf("pages gave %d agents, want %d", len(seen), total)
		}
		uniq := slices.Clone(seen)
		slices.Sort(uniq)
		if len(slices.Compact(uniq)) != total {
			t.Fatalf("duplicate agent in the pages: %v", seen)
		}
		a := x.newAgent("Role pages", "demo", "demo:agent", "extra:editor", "extra:viewer")
		var roles []string
		token = ""
		for range 4 {
			path := "/v1/agents/" + a + "/roles?pageSize=1"
			if token != "" {
				path += "&pageToken=" + url.QueryEscape(token)
			}
			resp, m := x.api(x.admin, http.MethodGet, path, nil)
			if resp.StatusCode != http.StatusOK || len(items(m)) != 1 {
				t.Fatalf("role page: %d %v", resp.StatusCode, m)
			}
			roles = append(roles, items(m)[0]["role"].(string))
			token, _ = m["nextPageToken"].(string)
			if token == "" {
				break
			}
		}
		if !slices.Equal(roles, []string{"demo:agent", "extra:editor", "extra:viewer"}) {
			t.Fatalf("roles = %v", roles)
		}
	})

	// I3: end to end with an agent.
	var userID, subject, agentID string
	t.Run("I3_end_to_end", func(t *testing.T) {
		userID, subject = x.subjectFor("i3", "extra:editor")
		agentID = x.newAgent("TechOrion AI", "demo", "extra:viewer")
		tok, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: agentID, Audience: "extra", Scopes: []string{extraRead}})
		if err != nil {
			t.Fatal(err)
		}
		p, err := x.verifier("extra").Verify(ctx, tok)
		if err != nil {
			t.Fatal(err)
		}
		if p.ID != userID || p.Type != auth.PrincipalUser || p.Act == nil || p.Act.ID != agentID || p.Act.Type != auth.PrincipalAgent ||
			!slices.Equal(p.Scopes, []string{extraRead}) || p.ClientID != "demo" {
			t.Fatalf("principal = %+v, act = %+v", p, p.Act)
		}
		// The user has write. The agent has not. The scope is the intersection.
		_, err = x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: agentID, Audience: "extra", Scopes: []string{extraRead, extraWrite}})
		wantOAuth(t, "scope the agent does not have", err, "invalid_scope")
		// The life is at most 5 minutes.
		_, claims := testserver.JWTClaims(t, tok)
		if life := claims["exp"].(float64) - claims["iat"].(float64); life > 300 || life < 10 {
			t.Fatalf("life = %v", life)
		}
		if _, has := claims["jti"]; !has {
			t.Fatal("no jti")
		}
		// The raw response has the headers and issued_token_type, and no refresh token.
		form := testserver.ExchangeForm(f.a.Assertion(t, demo, nil), "extra", extraRead, subject)
		form.Set("actor_token", agentID)
		form.Set("actor_token_type", domain.TokenTypeAgentID)
		form.Set("requested_token_type", domain.TokenTypeAccessToken)
		resp, body := f.a.PostToken(t, form)
		for _, want := range []string{`"issued_token_type":"` + domain.TokenTypeAccessToken + `"`, `"token_type":"Bearer"`, `"expires_in"`} {
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), want) {
				t.Fatalf("response: %d %s (want %s)", resp.StatusCode, body, want)
			}
		}
		if strings.Contains(string(body), "refresh_token") || strings.Contains(string(body), "id_token") ||
			resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
			t.Fatalf("response: %v %s", resp.Header, body)
		}
		// The success log record has the user, the agent, and the audience.
		var found bool
		for _, r := range f.a.logs.Records(t) {
			if r["event"] == "identity.token.exchange" && r["agent_id"] == agentID {
				found = r["user_id"] == userID && r["audience"] == "extra" && r["client.id"] == "demo" && r["jti"] != nil
			}
		}
		if !found {
			t.Fatal("no complete identity.token.exchange record")
		}
	})

	// I4: no agent.
	t.Run("I4_no_agent", func(t *testing.T) {
		tok, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, Audience: "extra", Scopes: []string{extraRead, extraWrite}})
		if err != nil {
			t.Fatal(err)
		}
		p, err := x.verifier("extra").Verify(ctx, tok)
		if err != nil || p.ID != userID || p.Act != nil || !slices.Equal(p.Scopes, []string{extraRead, extraWrite}) {
			t.Fatalf("principal = %+v, %v", p, err)
		}
		_, claims := testserver.JWTClaims(t, tok)
		if _, has := claims["act"]; has {
			t.Fatal("act is present")
		}
	})

	// I5: the verifier of another app refuses the token.
	t.Run("I5_wrong_audience", func(t *testing.T) {
		tok, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: agentID, Audience: "extra", Scopes: []string{extraRead}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.verifier("email").Verify(ctx, tok); !errors.Is(err, auth.ErrWrongAudience) {
			t.Fatalf("error = %v, want ErrWrongAudience", err)
		}
	})

	// I6: a disabled agent.
	t.Run("I6_disabled_agent", func(t *testing.T) {
		id := x.newAgent("To disable", "demo", "extra:viewer")
		if _, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: id, Audience: "extra", Scopes: []string{extraRead}}); err != nil {
			t.Fatal(err)
		}
		if resp, m := x.api(x.admin, http.MethodPatch, "/v1/agents/"+id, map[string]any{"enabled": false}); resp.StatusCode != 200 {
			t.Fatalf("disable: %d %v", resp.StatusCode, m)
		}
		_, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: id, Audience: "extra", Scopes: []string{extraRead}})
		wantOAuth(t, "disabled agent", err, "invalid_grant")
	})

	// I7: an agent of another client.
	t.Run("I7_other_client_agent", func(t *testing.T) {
		other := x.newAgent("Of extra", "extra", "extra:viewer")
		_, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: other, Audience: "extra", Scopes: []string{extraRead}})
		wantOAuth(t, "agent of another client", err, "invalid_grant")
		_, err = x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: "00000000-0000-4000-8000-0000000000e1", Audience: "extra", Scopes: []string{extraRead}})
		wantOAuth(t, "unknown agent", err, "invalid_grant")
	})

	// I8: the audience identity.
	t.Run("I8_audience_identity", func(t *testing.T) {
		for _, id := range []string{"", agentID} {
			_, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: id, Audience: "identity", Scopes: []string{"identity:api_token:manage_own"}})
			wantOAuth(t, "audience identity", err, "invalid_target")
		}
		_, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, Audience: "nomanifest", Scopes: []string{"nomanifest:a:b"}})
		wantOAuth(t, "app without a manifest", err, "invalid_target")
	})

	// I9: an exchanged token is not a subject token.
	t.Run("I9_exchange_of_exchanged", func(t *testing.T) {
		for name, id := range map[string]string{"with agent": agentID, "without agent": ""} {
			first, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: id, Audience: "extra", Scopes: []string{extraRead}})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			// The exchanged token has the audience demo and the client_id of the service client.
			for _, again := range []string{id, ""} {
				_, err = x.exchange(demo, auth.ExchangeRequest{SubjectToken: first, AgentID: again, Audience: "extra", Scopes: []string{extraRead}})
				wantOAuth(t, name+": exchanged token as subject", err, "invalid_grant")
			}
		}
	})

	// I9a: a user token of the app demo goes to the client of the app extra.
	t.Run("I9a_other_app", func(t *testing.T) {
		before := x.countWhere(`SELECT count(*) FROM client_assertion_jtis`)
		_, err := x.exchange(extra, auth.ExchangeRequest{SubjectToken: subject, Audience: "extra", Scopes: []string{extraRead}})
		wantOAuth(t, "token of another app", err, "invalid_grant")
		_, err = x.exchange(extra, auth.ExchangeRequest{SubjectToken: subject, Audience: "demo", Scopes: []string{"demo:ticket:read"}})
		wantOAuth(t, "token of another app, other audience", err, "invalid_grant")
		if x.countWhere(`SELECT count(*) FROM client_assertion_jtis`) <= before {
			t.Fatal("the client assertions were not used")
		}
	})

	// A token for the API of the identity service is not a subject token.
	t.Run("I9b_identity_token", func(t *testing.T) {
		access := x.adminToken(agentAdminScopes)
		_, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: access, Audience: "extra", Scopes: []string{extraRead}})
		wantOAuth(t, "token for the identity app", err, "invalid_grant")
		_, err = x.exchange(demo, auth.ExchangeRequest{SubjectToken: "cpat_" + strings.Repeat("A", 43), Audience: "extra", Scopes: []string{extraRead}})
		wantOAuth(t, "API token", err, "invalid_grant")
	})

	// I10: the user loses the role.
	t.Run("I10_user_role_removed", func(t *testing.T) {
		id, sub := x.subjectFor("i10", "extra:editor")
		ag := x.newAgent("I10 agent", "demo", "extra:editor")
		if _, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: sub, AgentID: ag, Audience: "extra", Scopes: []string{extraWrite}}); err != nil {
			t.Fatal(err)
		}
		if resp, m := x.api(x.admin, http.MethodDelete, "/v1/users/"+id+"/roles/extra:editor", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove role: %d %v", resp.StatusCode, m)
		}
		_, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: sub, AgentID: ag, Audience: "extra", Scopes: []string{extraWrite}})
		wantOAuth(t, "user without the role", err, "invalid_scope")
	})

	// I10a: the manifest does not have the role of the agent any more.
	t.Run("I10a_pending_agent_role", func(t *testing.T) {
		_, sub := x.subjectFor("i10a", "extra:editor")
		tok := token(t, f.a.Server, extra, "identity", "identity:manifest:publish")
		with := manifestJSON(t, "extra", []string{"extra:item:read", "extra:item:write"}, []string{"viewer", "editor", "temp"},
			map[string][]string{"viewer": {"extra:item:read"}, "editor": {"extra:item:read", "extra:item:write"}, "temp": {"extra:item:read"}})
		if resp, m := publish(t, f.a.Server, tok, "extra", with); resp.StatusCode != http.StatusOK {
			t.Fatalf("publish with temp: %d %v", resp.StatusCode, m)
		}
		ag := x.newAgent("I10a agent", "demo", "extra:temp")
		if _, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: sub, AgentID: ag, Audience: "extra", Scopes: []string{extraRead}}); err != nil {
			t.Fatal(err)
		}
		tok = token(t, f.a.Server, extra, "identity", "identity:manifest:publish")
		without := manifestJSON(t, "extra", []string{"extra:item:read", "extra:item:write"}, []string{"viewer", "editor"},
			map[string][]string{"viewer": {"extra:item:read"}, "editor": {"extra:item:read", "extra:item:write"}})
		if resp, m := publish(t, f.a.Server, tok, "extra", without); resp.StatusCode != http.StatusOK {
			t.Fatalf("publish without temp: %d %v", resp.StatusCode, m)
		}
		_, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: sub, AgentID: ag, Audience: "extra", Scopes: []string{extraRead}})
		wantOAuth(t, "pending role", err, "invalid_scope")
		resp, m := x.api(x.admin, http.MethodGet, "/v1/agents/"+ag+"/roles", nil)
		if resp.StatusCode != 200 || len(items(m)) != 1 || items(m)[0]["pending"] != true {
			t.Fatalf("role list: %d %v", resp.StatusCode, m)
		}
	})

	// I10b: a disabled user and an invited user.
	t.Run("I10b_user_status", func(t *testing.T) {
		id, sub := x.subjectFor("i10b", "extra:editor")
		for _, st := range []string{"disabled", "invited", "active"} {
			if _, err := f.a.Pool(t).Exec(ctx, `UPDATE users SET status = $2 WHERE id = $1`, id, st); err != nil {
				t.Fatal(err)
			}
			_, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: sub, Audience: "extra", Scopes: []string{extraRead}})
			if st == "active" {
				if err != nil {
					t.Fatalf("active: %v", err)
				}
				continue
			}
			wantOAuth(t, "user "+st, err, "invalid_grant")
		}
	})

	// I13: an exchanged token on the identity API and on userinfo.
	t.Run("I13_userinfo_and_v1", func(t *testing.T) {
		for name, id := range map[string]string{"with agent": agentID, "without agent": ""} {
			tok, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: id, Audience: "extra", Scopes: []string{extraRead}})
			if err != nil {
				t.Fatal(err)
			}
			if resp, _ := f.a.Do(t, http.MethodGet, "/v1/me/api-tokens", tok, ""); resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s: /v1/me/api-tokens: %d", name, resp.StatusCode)
			}
			if resp, _ := f.a.Do(t, http.MethodGet, "/oauth/userinfo", tok, ""); resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s: /oauth/userinfo: %d", name, resp.StatusCode)
			}
		}
		if resp, b := f.a.Do(t, http.MethodGet, "/oauth/userinfo", subject, ""); resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "i3@example.com") {
			t.Errorf("code flow token on userinfo: %d %s", resp.StatusCode, b)
		}
	})

	// The request rules on the wire.
	t.Run("raw_request_rules", func(t *testing.T) {
		base := func() url.Values {
			return testserver.ExchangeForm(f.a.Assertion(t, demo, nil), "extra", extraRead, subject)
		}
		post := func(form url.Values) (int, string) {
			resp, body := f.a.PostToken(t, form)
			return resp.StatusCode, string(body)
		}
		if st, b := post(base()); st != 200 {
			t.Fatalf("base request: %d %s", st, b)
		}
		for name, change := range map[string]func(url.Values){
			"repeated subject_token": func(v url.Values) { v.Add("subject_token", subject) },
			"repeated audience":      func(v url.Values) { v.Add("audience", "extra") },
			"repeated scope":         func(v url.Values) { v.Add("scope", extraRead) },
			"repeated actor_token": func(v url.Values) {
				v.Add("actor_token", agentID)
				v.Add("actor_token", agentID)
				v.Set("actor_token_type", domain.TokenTypeAgentID)
			},
			"actor token only": func(v url.Values) { v.Set("actor_token", agentID) },
			"client_secret":    func(v url.Values) { v.Set("client_secret", "x") },
			"missing subject":  func(v url.Values) { v.Del("subject_token") },
		} {
			v := base()
			change(v)
			if st, b := post(v); st != http.StatusBadRequest || !strings.Contains(b, "invalid_request") {
				t.Errorf("%s: %d %s", name, st, b)
			}
		}
		v := base()
		v.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
		if st, b := post(v); st != http.StatusBadRequest || !strings.Contains(b, "unsupported_token_type") {
			t.Errorf("subject_token_type: %d %s", st, b)
		}
		v = base()
		v.Set("client_assertion", "bad")
		if st, b := post(v); st != http.StatusUnauthorized || !strings.Contains(b, "invalid_client") {
			t.Errorf("bad assertion: %d %s", st, b)
		}
		// A used jti.
		v = base()
		if st, _ := post(v); st != 200 {
			t.Fatal("first use")
		}
		if st, b := post(v); st != http.StatusUnauthorized || !strings.Contains(b, "invalid_client") {
			t.Errorf("used jti: %d %s", st, b)
		}
		// The discovery document has the grant type.
		if _, b := f.a.Get(t, "/.well-known/openid-configuration"); !strings.Contains(string(b), domain.GrantTypeTokenExchange) {
			t.Errorf("discovery: %s", b)
		}
	})

	// I14: the secret ledger.
	t.Run("I14_no_secrets_in_telemetry", func(t *testing.T) {
		h.ledger.mu.Lock()
		defer h.ledger.mu.Unlock()
		if len(h.ledger.exchange) < 20 {
			t.Fatalf("the ledger has %d values", len(h.ledger.exchange))
		}
		var texts []string
		for _, l := range h.ledger.logs {
			texts = append(texts, l.Text())
		}
		spans, exchangeSpans := "", ""
		for _, s := range spanExporter.GetSpans() {
			before := len(spans)
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
			if s.Name == "executor:TokenExchange" {
				exchangeSpans += spans[before:]
			}
		}
		for _, v := range h.ledger.exchange {
			if v == "" {
				continue
			}
			for _, text := range texts {
				if strings.Contains(text, v) {
					t.Fatalf("a log record holds a token (%s...)", v[:8])
				}
			}
			if strings.Contains(spans, v) {
				t.Fatalf("a span holds a token (%s...)", v[:8])
			}
		}
		// The agent ID is in the delegation record, and in no attribute of the
		// span of the use case. The spans of the admin API have the ID in the path.
		if exchangeSpans == "" || strings.Contains(exchangeSpans, agentID) || strings.Contains(exchangeSpans, userID) {
			t.Fatalf("the spans of the use case: %q", exchangeSpans)
		}
		if !strings.Contains(strings.Join(texts, "\n"), "identity.token.exchange") {
			t.Fatal("no delegation record")
		}
	})
}

// I12: a failure of the jti store gives temporarily_unavailable. The store is a
// table of PostgreSQL. The test renames the table on an own server.
func TestIssue10StoreFailureIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h)
	x := newExchangeFixture(t, h, f)
	x.grantExchange("demo")
	_, subject := x.subjectFor("i12", "extra:editor")
	if _, err := f.a.Pool(t).Exec(ctx, `ALTER TABLE client_assertion_jtis RENAME TO client_assertion_jtis_off`); err != nil {
		t.Fatal(err)
	}
	_, err := x.exchange(f.serviceClient, auth.ExchangeRequest{SubjectToken: subject, Audience: "extra", Scopes: []string{extraRead}})
	if !errors.Is(err, auth.ErrTokenUnavailable) {
		t.Fatalf("error = %v, want ErrTokenUnavailable", err)
	}
	var oe *auth.OAuthError
	if errors.As(err, &oe) {
		t.Fatalf("error = %v, want no OAuthError", err)
	}
}

// I1: migration 0011 up and down on a database with data of 0010.
func TestIssue10MigrationIntegration(t *testing.T) {
	env := testserver.NewEnv(t)
	u, _ := env.PG.NewDatabase(t)
	pool, err := pgxpool.New(ctx, string(u))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrations(t, pool, 1, 10)
	if _, err := pool.Exec(ctx, `INSERT INTO clients (id, type, app, name, disabled, source, created_at, updated_at)
		VALUES ('svc', 'service', 'demo', 'Svc', false, 'api', now(), now())`); err != nil {
		t.Fatal(err)
	}
	applyMigrations(t, pool, 11, 11)
	const agent = "00000000-0000-4000-8000-0000000000a1"
	if _, err := pool.Exec(ctx, `INSERT INTO agents (id, name, client_id, enabled, created_at, updated_at) VALUES ($1, 'A', 'svc', true, now(), now())`, agent); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"duplicate name": `INSERT INTO agents (id, name, client_id, enabled, created_at, updated_at) VALUES ('00000000-0000-4000-8000-0000000000a2', 'A', 'svc', true, now(), now())`,
		"unknown client": `INSERT INTO agents (id, name, client_id, enabled, created_at, updated_at) VALUES ('00000000-0000-4000-8000-0000000000a3', 'B', 'none', true, now(), now())`,
		"empty name":     `INSERT INTO agents (id, name, client_id, enabled, created_at, updated_at) VALUES ('00000000-0000-4000-8000-0000000000a4', '', 'svc', true, now(), now())`,
		"bad source":     `INSERT INTO agent_roles (agent_id, app, role, source) VALUES ('` + agent + `', 'extra', 'viewer', 'other')`,
		"unknown agent":  `INSERT INTO agent_roles (agent_id, app, role, source) VALUES ('00000000-0000-4000-8000-0000000000a5', 'extra', 'viewer', 'api')`,
	} {
		if _, err := pool.Exec(ctx, q); err == nil {
			t.Errorf("%s must fail", name)
		}
	}
	// A role that is not in a manifest is allowed (pending).
	if _, err := pool.Exec(ctx, `INSERT INTO agent_roles (agent_id, app, role, source) VALUES ($1, 'ghost', 'role', 'api')`, agent); err != nil {
		t.Fatal(err)
	}
	down, err := migrations.Files.ReadFile("0011_agents.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('agents', 'agent_roles')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tables after the down: %d, %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM clients`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("clients after the down: %d, %v", n, err)
	}
}
