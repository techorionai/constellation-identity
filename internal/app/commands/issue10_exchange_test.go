package commands_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/techorionai/constellation-identity/internal/adapters/jose"
	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/tokensigner"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

const (
	agent1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	agent2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

var (
	roleMailUser  = domain.RoleRef{App: "mail", Role: "user"}
	roleMailAgent = domain.RoleRef{App: "mail", Role: "agent"}
	roleMailGone  = domain.RoleRef{App: "mail", Role: "gone"}
)

// keySet gives the signing key and the public keys of the test.
type keySet struct {
	t   *testing.T
	f   *fixture
	key tokensigner.Key
}

func (k keySet) ActiveKey() (tokensigner.Key, error) { return k.key, nil }
func (k keySet) JWKS() []domain.PublicJWK            { return []domain.PublicJWK{jwkOf(k.t, k.f.sign, "sig-1")} }

// exchangeEnv is the setup of the token exchange tests. The client helpdesk
// has the permission to exchange. The user 1 has the role mail:user. The agent
// 1 has the role mail:agent and belongs to the client helpdesk.
type exchangeEnv struct {
	*fixture
	users  *mock.Users
	roles  *mock.UserRoles
	agents *mock.Agents
	aroles *mock.AgentRoles
	cmd    *commands.TokenExchangeCommand
	log    *bytes.Buffer
}

func newExchangeEnv(t *testing.T) *exchangeEnv {
	t.Helper()
	f := newFixture(t)
	f.roles.assigned = append(f.roles.assigned, "identity:token:exchange")
	f.clients.clients["helpdesk-ui"] = domain.Client{ID: "helpdesk-ui", Type: domain.ClientTypePublic, App: "helpdesk"}
	f.clients.clients["helpdesk-off"] = domain.Client{ID: "helpdesk-off", Type: domain.ClientTypePublic, App: "helpdesk", Disabled: true}
	f.clients.clients["other-ui"] = domain.Client{ID: "other-ui", Type: domain.ClientTypePublic, App: "other"}
	e := &exchangeEnv{fixture: f, users: mock.NewUsers(), agents: mock.NewAgents(), aroles: mock.NewAgentRoles(), log: &bytes.Buffer{}}
	e.users.Rows[user1] = domain.User{ID: user1, Email: "one@example.com", Name: "One", Status: domain.UserActive}
	e.roles = mock.NewUserRoles(e.users)
	e.roles.Perms[domain.UserRole] = []string{"identity:api_token:manage_own"}
	e.roles.Perms[roleMailUser] = []string{"mail:message:read", "mail:message:write", "mail:draft:read"}
	e.roles.Rows[user1] = []domain.RoleRef{roleMailUser}
	e.aroles.Perms[roleMailAgent] = []string{"mail:message:read", "mail:other:read"}
	e.aroles.Rows[agent1] = []domain.RoleRef{roleMailAgent}
	e.agents.Rows[agent1] = domain.Agent{ID: agent1, Name: "Agent", ClientID: "helpdesk", Enabled: true}
	e.agents.Rows[agent2] = domain.Agent{ID: agent2, Name: "Other agent", ClientID: "other", Enabled: true}
	e.cmd = e.newCommand(t)
	return e
}

func (e *exchangeEnv) newCommand(t *testing.T) *commands.TokenExchangeCommand {
	t.Helper()
	n := 0
	cmd, err := commands.NewTokenExchange(commands.TokenExchangeDeps{
		Issuer: issuer, Auth: e.fixture.cmd, Clients: e.clients, ClientRoles: e.fixture.roles,
		Manifests: &fakeManifests{apps: map[string]bool{"mail": true, "identity": true}},
		Users:     e.users, UserRoles: e.roles, Agents: e.agents, AgentRoles: e.aroles,
		Keys:   keySet{t: t, f: e.fixture, key: tokensigner.Key{KID: "sig-1", Private: e.sign}},
		Signer: jose.Signer{}, Verifier: jose.Verifier{},
		Log:   slog.New(slog.NewTextHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:   func() time.Time { return now },
		NewID: func() string { n++; return fmt.Sprintf("exchanged-%d", n) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

// subject signs a user access token that the code flow of the client
// helpdesk-ui would make. change edits the claims. A nil value deletes one.
func (e *exchangeEnv) subject(t *testing.T, change func(c map[string]any)) string {
	t.Helper()
	c := domain.UserAccessToken{
		Issuer: issuer, Audience: "helpdesk", UserID: user1, ClientID: "helpdesk-ui",
		Scopes: []string{"helpdesk:ticket:read"}, Now: now, TTL: 15 * time.Minute, JTI: "subject-jti",
	}.Claims()
	if change != nil {
		change(c)
	}
	for k, v := range c {
		if v == nil {
			delete(c, k)
		}
	}
	tok, err := jose.Signer{}.Sign(tokensigner.Key{KID: "sig-1", Private: e.sign}, c, map[string]any{"typ": domain.AccessTokenType})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// in makes a valid request with no actor.
func (e *exchangeEnv) in(t *testing.T) commands.TokenExchange {
	t.Helper()
	return commands.TokenExchange{
		AssertionType: domain.AssertionType, Assertion: e.assertion(t, nil),
		SubjectToken: e.subject(t, nil), SubjectTokenType: domain.TokenTypeAccessToken,
		Audience: "mail", Scope: "mail:message:read",
	}
}

func (e *exchangeEnv) withAgent(in commands.TokenExchange, id string) commands.TokenExchange {
	in.ActorToken, in.ActorTokenType = id, domain.TokenTypeAgentID
	return in
}

func wantCode(t *testing.T, what string, err error, code string) {
	t.Helper()
	oe, ok := apperrors.AsOAuthError(err)
	if !ok || oe.Code != code {
		t.Errorf("%s: error = %v, want the code %s", what, err, code)
	}
}

func decodePart(t *testing.T, part string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// claimsOf reads the claims of an issued token.
func claimsOf(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token = %q", tok)
	}
	return decodePart(t, parts[1])
}

// Issue10_U1: the claims of an exchanged token, with and without an actor.
func TestIssue10_U1_Claims(t *testing.T) {
	e := newExchangeEnv(t)
	res, err := e.cmd.Execute(ctx, e.in(t))
	if err != nil {
		t.Fatal(err)
	}
	c := claimsOf(t, res.AccessToken)
	if _, has := c["act"]; has || c["sub"] != user1 || c["principal_type"] != "user" || c["aud"] != "mail" ||
		c["client_id"] != "helpdesk" || c["iss"] != issuer || c["scope"] != "mail:message:read" || c["jti"] != "exchanged-1" ||
		c["nbf"] == nil || c["iat"] == nil {
		t.Fatalf("claims without actor = %v", c)
	}
	if res.IssuedTokenType != domain.TokenTypeAccessToken || res.Scope != "mail:message:read" {
		t.Fatalf("result = %+v", res)
	}
	res, err = e.cmd.Execute(ctx, e.withAgent(e.in(t), agent1))
	if err != nil {
		t.Fatal(err)
	}
	act, _ := claimsOf(t, res.AccessToken)["act"].(map[string]any)
	if len(act) != 2 || act["sub"] != agent1 || act["principal_type"] != "agent" {
		t.Fatalf("act = %v", act)
	}
	if claimsOf(t, res.AccessToken)["sub"] != user1 {
		t.Fatal("sub must be the user")
	}
}

// Issue10_U2: the lifetime is the lower value of 5 minutes and the subject exp.
func TestIssue10_U2_Lifetime(t *testing.T) {
	for remaining, want := range map[time.Duration]int{
		4 * time.Minute: 240, 2 * time.Minute: 120, 10 * time.Second: 10, 15 * time.Minute: 300, 5 * time.Minute: 300,
	} {
		e := newExchangeEnv(t)
		in := e.in(t)
		in.SubjectToken = e.subject(t, func(c map[string]any) { c["exp"] = now.Add(remaining).Unix() })
		res, err := e.cmd.Execute(ctx, in)
		if err != nil {
			t.Fatalf("%v left: %v", remaining, err)
		}
		c := claimsOf(t, res.AccessToken)
		if got := int64(c["exp"].(float64)) - now.Unix(); got != int64(want) || res.ExpiresIn != want || res.ExpiresIn < 10 {
			t.Errorf("%v left: exp - iat = %d, expires_in = %d, want %d", remaining, got, res.ExpiresIn, want)
		}
	}
}

// Issue10_U2a: a subject token with less than 10 s left is refused.
func TestIssue10_U2a_MinimumLife(t *testing.T) {
	for left, ok := range map[time.Duration]bool{9 * time.Second: false, 10 * time.Second: true, 11 * time.Second: true} {
		e := newExchangeEnv(t)
		in := e.in(t)
		in.SubjectToken = e.subject(t, func(c map[string]any) { c["exp"] = now.Add(left).Unix() })
		_, err := e.cmd.Execute(ctx, in)
		if ok && err != nil {
			t.Errorf("%v left: %v", left, err)
		}
		if !ok {
			wantCode(t, left.String(), err, apperrors.OAuthInvalidGrant)
		}
	}
}

// Issue10_U3_U4_U5: the scope is the intersection of the user and the agent.
func TestIssue10_U3_Scope(t *testing.T) {
	e := newExchangeEnv(t)
	// U3: the user has read, write, and draft. The agent has read and other.
	in := e.withAgent(e.in(t), agent1)
	in.Scope = "mail:message:read"
	if res, err := e.cmd.Execute(ctx, in); err != nil || res.Scope != "mail:message:read" {
		t.Fatalf("U3: %+v, %v", res, err)
	}
	// U4: write is only for the user.
	for _, s := range []string{"mail:message:write", "mail:other:read", "mail:message:read mail:message:write", "openid", "mail:message:read openid", "helpdesk:ticket:read"} {
		in.Scope, in.Assertion = s, e.assertion(t, nil)
		_, err := e.cmd.Execute(ctx, in)
		wantCode(t, "U4 "+s, err, apperrors.OAuthInvalidScope)
	}
	// U5: with no actor, the user scopes count.
	no := e.in(t)
	no.Scope = "mail:message:write mail:draft:read"
	res, err := e.cmd.Execute(ctx, no)
	if err != nil || res.Scope != "mail:message:write mail:draft:read" {
		t.Fatalf("U5: %+v, %v", res, err)
	}
	no.Scope, no.Assertion = "mail:other:read", e.assertion(t, nil)
	_, err = e.cmd.Execute(ctx, no)
	wantCode(t, "U5 agent only scope", err, apperrors.OAuthInvalidScope)
}

// Issue10_U5a: a pending role of the agent gives no permission.
func TestIssue10_U5a_PendingAgentRole(t *testing.T) {
	e := newExchangeEnv(t)
	delete(e.aroles.Perms, roleMailAgent)
	in := e.withAgent(e.in(t), agent1)
	_, err := e.cmd.Execute(ctx, in)
	wantCode(t, "pending role", err, apperrors.OAuthInvalidScope)
}

// Issue10_U6: a client without the permission gets unauthorized_client, also
// for a request with missing parameters.
func TestIssue10_U6_NoPermission(t *testing.T) {
	e := newExchangeEnv(t)
	e.fixture.roles.assigned = []string{"demo:ticket:read"}
	_, err := e.cmd.Execute(ctx, e.in(t))
	wantCode(t, "no permission", err, apperrors.OAuthUnauthorizedClient)
	in := e.in(t)
	in.SubjectToken, in.Scope = "", ""
	_, err = e.cmd.Execute(ctx, in)
	wantCode(t, "no permission, missing parameters", err, apperrors.OAuthUnauthorizedClient)
}

// Issue10_U7: the token types.
func TestIssue10_U7_TokenTypes(t *testing.T) {
	e := newExchangeEnv(t)
	for name, change := range map[string]func(*commands.TokenExchange){
		"subject_token_type":   func(in *commands.TokenExchange) { in.SubjectTokenType = "urn:ietf:params:oauth:token-type:jwt" },
		"requested_token_type": func(in *commands.TokenExchange) { in.RequestedTokenType = "urn:ietf:params:oauth:token-type:jwt" },
		"actor_token_type": func(in *commands.TokenExchange) {
			in.ActorToken, in.ActorTokenType = agent1, domain.TokenTypeAccessToken
		},
	} {
		in := e.in(t)
		change(&in)
		_, err := e.cmd.Execute(ctx, in)
		wantCode(t, name, err, apperrors.OAuthUnsupportedTokenType)
	}
	in := e.in(t)
	in.RequestedTokenType = domain.TokenTypeAccessToken
	if _, err := e.cmd.Execute(ctx, in); err != nil {
		t.Fatalf("requested_token_type access token: %v", err)
	}
}

// Issue10_U8: the actor token and its type appear together.
func TestIssue10_U8_ActorPair(t *testing.T) {
	e := newExchangeEnv(t)
	in := e.in(t)
	in.ActorToken = agent1
	_, err := e.cmd.Execute(ctx, in)
	wantCode(t, "token only", err, apperrors.OAuthInvalidRequest)
	in = e.in(t)
	in.ActorTokenType = domain.TokenTypeAgentID
	_, err = e.cmd.Execute(ctx, in)
	wantCode(t, "type only", err, apperrors.OAuthInvalidRequest)
}

// Issue10_U8a: the required parameters.
func TestIssue10_U8a_Required(t *testing.T) {
	e := newExchangeEnv(t)
	for name, change := range map[string]func(*commands.TokenExchange){
		"subject_token":      func(in *commands.TokenExchange) { in.SubjectToken = "" },
		"subject_token_type": func(in *commands.TokenExchange) { in.SubjectTokenType = "" },
		"audience":           func(in *commands.TokenExchange) { in.Audience = "" },
		"scope":              func(in *commands.TokenExchange) { in.Scope = "" },
		"scope of spaces":    func(in *commands.TokenExchange) { in.Scope = "   " },
	} {
		in := e.in(t)
		change(&in)
		_, err := e.cmd.Execute(ctx, in)
		wantCode(t, name, err, apperrors.OAuthInvalidRequest)
	}
}

// Issue10_U9: the subject token checks.
func TestIssue10_U9_Subject(t *testing.T) {
	e := newExchangeEnv(t)
	other := newKey(t)
	forged, err := jose.Signer{}.Sign(tokensigner.Key{KID: "sig-1", Private: other}, map[string]any{
		"iss": issuer, "sub": user1, "aud": "helpdesk", "exp": now.Add(time.Hour).Unix(), "client_id": "helpdesk-ui", "principal_type": "user",
	}, map[string]any{"typ": domain.AccessTokenType})
	if err != nil {
		t.Fatal(err)
	}
	wrongTyp, _ := jose.Signer{}.Sign(tokensigner.Key{KID: "sig-1", Private: e.sign}, domain.UserAccessToken{
		Issuer: issuer, Audience: "helpdesk", UserID: user1, ClientID: "helpdesk-ui", Now: now, TTL: time.Hour, JTI: "j",
	}.Claims(), map[string]any{"typ": "JWT"})
	cases := map[string]string{
		"bad signature":    forged,
		"wrong typ":        wrongTyp,
		"wrong issuer":     e.subject(t, func(c map[string]any) { c["iss"] = "https://evil.example.com" }),
		"expired":          e.subject(t, func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }),
		"no exp":           e.subject(t, func(c map[string]any) { c["exp"] = nil }),
		"nbf in future":    e.subject(t, func(c map[string]any) { c["nbf"] = now.Add(time.Minute).Unix() }),
		"service token":    e.subject(t, func(c map[string]any) { c["principal_type"] = "service" }),
		"not a jwt":        "not-a-token",
		"api token":        "cpat_" + strings.Repeat("A", 43),
		"user not in db":   e.subject(t, func(c map[string]any) { c["sub"] = "33333333-3333-4333-8333-333333333333" }),
		"sub not a UUID":   e.subject(t, func(c map[string]any) { c["sub"] = "x" }),
		"missing nothing?": "",
	}
	delete(cases, "missing nothing?")
	for name, tok := range cases {
		in := e.in(t)
		in.SubjectToken = tok
		_, err := e.cmd.Execute(ctx, in)
		wantCode(t, name, err, apperrors.OAuthInvalidGrant)
	}
	for _, status := range []domain.UserStatus{domain.UserDisabled, domain.UserInvited} {
		u := e.users.Rows[user1]
		u.Status = status
		e.users.Rows[user1] = u
		_, err := e.cmd.Execute(ctx, e.in(t))
		wantCode(t, "user "+string(status), err, apperrors.OAuthInvalidGrant)
	}
}

// Issue10_U9a: act in any JSON form.
func TestIssue10_U9a_Act(t *testing.T) {
	e := newExchangeEnv(t)
	for name, v := range map[string]any{
		"object": map[string]any{"sub": agent1}, "string": "x", "number": 1, "null": nil,
	} {
		in := e.in(t)
		in.SubjectToken = e.subject(t, func(c map[string]any) { c["act"] = v })
		// A nil value deletes a claim in the helper, so the null case is signed here.
		if name == "null" {
			cl := domain.UserAccessToken{Issuer: issuer, Audience: "helpdesk", UserID: user1, ClientID: "helpdesk-ui", Now: now, TTL: time.Hour, JTI: "j"}.Claims()
			cl["act"] = nil
			tok, err := jose.Signer{}.Sign(tokensigner.Key{KID: "sig-1", Private: e.sign}, cl, map[string]any{"typ": domain.AccessTokenType})
			if err != nil {
				t.Fatal(err)
			}
			in.SubjectToken = tok
		}
		_, err := e.cmd.Execute(ctx, in)
		wantCode(t, "act "+name, err, apperrors.OAuthInvalidGrant)
		c, err := (jose.Verifier{}).Verify(in.SubjectToken, e.keysForTest(t))
		if err != nil || !c.HasAct {
			t.Errorf("act %s: HasAct = %v, err = %v", name, c.HasAct, err)
		}
	}
}

func (e *exchangeEnv) keysForTest(t *testing.T) []domain.PublicJWK {
	return keySet{t: t, f: e.fixture}.JWKS()
}

// Issue10_U9b: the client of the subject token.
func TestIssue10_U9b_SubjectClient(t *testing.T) {
	e := newExchangeEnv(t)
	for name, id := range map[string]string{"service client (an exchanged token)": "helpdesk", "unknown client": "nobody", "disabled public client": "helpdesk-off", "no client": ""} {
		in := e.in(t)
		in.SubjectToken = e.subject(t, func(c map[string]any) { c["client_id"] = id })
		_, err := e.cmd.Execute(ctx, in)
		wantCode(t, name, err, apperrors.OAuthInvalidGrant)
	}
	// The result of a first exchange is not a subject token, with or without an actor.
	for _, actor := range []string{"", agent1} {
		in := e.in(t)
		if actor != "" {
			in = e.withAgent(in, actor)
		}
		res, err := e.cmd.Execute(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		again := e.in(t)
		again.SubjectToken = res.AccessToken
		_, err = e.cmd.Execute(ctx, again)
		wantCode(t, "exchange of an exchanged token", err, apperrors.OAuthInvalidGrant)
	}
}

// Issue10_U9c: the audience of the subject token is the app of the client.
func TestIssue10_U9c_SubjectAudience(t *testing.T) {
	e := newExchangeEnv(t)
	for name, aud := range map[string]any{
		"other app": "other", "two values": []string{"helpdesk", "other"}, "no audience": nil, "empty list": []string{},
	} {
		in := e.in(t)
		in.SubjectToken = e.subject(t, func(c map[string]any) { c["aud"] = aud })
		_, err := e.cmd.Execute(ctx, in)
		wantCode(t, name, err, apperrors.OAuthInvalidGrant)
	}
	in := e.in(t)
	in.SubjectToken = e.subject(t, func(c map[string]any) { c["aud"] = []string{"helpdesk"} })
	if _, err := e.cmd.Execute(ctx, in); err != nil {
		t.Fatalf("one audience in a list: %v", err)
	}
}

// Issue10_U9d: a token for the app identity is not a subject token.
func TestIssue10_U9d_IdentityAudience(t *testing.T) {
	e := newExchangeEnv(t)
	in := e.in(t)
	in.SubjectToken = e.subject(t, func(c map[string]any) { c["aud"] = "identity"; c["client_id"] = "helpdesk-ui" })
	_, err := e.cmd.Execute(ctx, in)
	wantCode(t, "aud identity", err, apperrors.OAuthInvalidGrant)
}

// Issue10_U10: each agent problem gives the same error and no database error.
func TestIssue10_U10_Agent(t *testing.T) {
	e := newExchangeEnv(t)
	e.agents.Rows["cccccccc-cccc-4ccc-8ccc-cccccccccccc"] = domain.Agent{ID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Name: "Off", ClientID: "helpdesk"}
	var texts []string
	before := e.agents.GetCalls
	for name, id := range map[string]string{
		"unknown":        "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		"disabled":       "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"another client": agent2,
		"x":              "x",
		"spaces":         " " + agent1 + " ",
		"braces":         "{" + agent1 + "}",
		"no hyphens":     strings.ReplaceAll(agent1, "-", ""),
	} {
		_, err := e.cmd.Execute(ctx, e.withAgent(e.in(t), id))
		wantCode(t, name, err, apperrors.OAuthInvalidGrant)
		if oe, ok := apperrors.AsOAuthError(err); ok {
			texts = append(texts, oe.Description)
		}
	}
	for _, d := range texts {
		if d != texts[0] {
			t.Fatalf("error texts differ: %q and %q", d, texts[0])
		}
	}
	if e.agents.GetCalls-before != 3 {
		t.Errorf("repository calls = %d, want 3 (a value that is not a UUID gets no query)", e.agents.GetCalls-before)
	}
}

// Issue10_U11: the audience.
func TestIssue10_U11_Audience(t *testing.T) {
	e := newExchangeEnv(t)
	for name, aud := range map[string]string{"identity": "identity", "no manifest": "calendar", "not an app key": "Mail App!", "two apps": "mail other"} {
		in := e.in(t)
		in.Audience = aud
		_, err := e.cmd.Execute(ctx, in)
		wantCode(t, name, err, apperrors.OAuthInvalidTarget)
	}
}

// Issue10_U11a_U12: a repeated parameter and a second authentication method.
func TestIssue10_U11a_Repeated(t *testing.T) {
	e := newExchangeEnv(t)
	in := e.in(t)
	in.RepeatedParameter = true
	_, err := e.cmd.Execute(ctx, in)
	wantCode(t, "repeated", err, apperrors.OAuthInvalidRequest)
	in = e.in(t)
	in.SecondAuthentication = true
	_, err = e.cmd.Execute(ctx, in)
	wantCode(t, "second authentication", err, apperrors.OAuthInvalidRequest)
}

// Issue10_U12a: client authentication problems of the request.
func TestIssue10_U12a_AssertionRequest(t *testing.T) {
	e := newExchangeEnv(t)
	for name, change := range map[string]func(*commands.TokenExchange){
		"wrong assertion type":   func(in *commands.TokenExchange) { in.AssertionType = "urn:other" },
		"missing assertion type": func(in *commands.TokenExchange) { in.AssertionType = "" },
		"empty assertion":        func(in *commands.TokenExchange) { in.Assertion = "" },
	} {
		in := e.in(t)
		change(&in)
		_, err := e.cmd.Execute(ctx, in)
		wantCode(t, name, err, apperrors.OAuthInvalidRequest)
	}
}

// Issue10_U12b: client authentication failures.
func TestIssue10_U12b_ClientFailures(t *testing.T) {
	e := newExchangeEnv(t)
	for name, change := range map[string]func(*exchangeEnv, *commands.TokenExchange){
		"public client": func(e *exchangeEnv, in *commands.TokenExchange) {
			in.Assertion = e.assertion(t, func(c map[string]any) { c["iss"], c["sub"] = "web", "web" })
		},
		"unknown client": func(e *exchangeEnv, in *commands.TokenExchange) {
			in.Assertion = e.assertion(t, func(c map[string]any) { c["iss"], c["sub"] = "nobody", "nobody" })
		},
		"bad signature": func(e *exchangeEnv, in *commands.TokenExchange) {
			in.Assertion = signES256(t, newKey(t), "k1", map[string]any{
				"iss": "helpdesk", "sub": "helpdesk", "aud": issuer, "jti": "x", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
		},
		"disabled client": func(e *exchangeEnv, in *commands.TokenExchange) {
			in.Assertion = e.assertion(t, func(c map[string]any) { c["iss"], c["sub"] = "off", "off" })
		},
		"used jti": func(e *exchangeEnv, in *commands.TokenExchange) {
			in.Assertion = e.assertion(t, func(c map[string]any) { c["jti"] = "same" })
			if _, err := e.cmd.Execute(ctx, *in); err != nil {
				t.Fatal(err)
			}
		},
	} {
		in := e.in(t)
		change(e, &in)
		_, err := e.cmd.Execute(ctx, in)
		wantCode(t, name, err, apperrors.OAuthInvalidClient)
	}
}

// Issue10_U12c: a failure of the jti store gives temporarily_unavailable.
func TestIssue10_U12c_JTIStore(t *testing.T) {
	e := newExchangeEnv(t)
	e.jti.err = errors.New("valkey is down")
	_, err := e.cmd.Execute(ctx, e.in(t))
	wantCode(t, "jti store", err, apperrors.OAuthTemporarilyUnavailable)
	if oe, _ := apperrors.AsOAuthError(err); oe == nil || oe.Status() != 503 {
		t.Fatalf("error = %v, want status 503", err)
	}
}

// Issue10_U15: the counters have with_agent and no ID.
func TestIssue10_U15_Counters(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	old := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	defer otel.SetMeterProvider(old)
	e := newExchangeEnv(t)
	if _, err := e.cmd.Execute(ctx, e.in(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.cmd.Execute(ctx, e.withAgent(e.in(t), agent1)); err != nil {
		t.Fatal(err)
	}
	bad := e.withAgent(e.in(t), agent2)
	_, _ = e.cmd.Execute(ctx, bad)
	bad = e.in(t)
	bad.Scope = "mail:nothing:here"
	_, _ = e.cmd.Execute(ctx, bad)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	type key struct {
		name, errCode, agent string
	}
	got := map[key]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				k := key{name: m.Name}
				for _, kv := range dp.Attributes.ToSlice() {
					switch kv.Key {
					case "with_agent":
						k.agent = kv.Value.String()
					case "error":
						k.errCode = kv.Value.String()
					case "grant_type":
						if kv.Value.String() != "token_exchange" {
							t.Errorf("grant_type = %s", kv.Value.String())
						}
					case "principal_type":
						if kv.Value.String() != "user" {
							t.Errorf("principal_type = %s", kv.Value.String())
						}
					default:
						t.Errorf("unexpected attribute %s", kv.Key)
					}
				}
				got[k] += dp.Value
			}
		}
	}
	want := map[key]int64{
		{"identity.tokens.issued", "", "false"}:             1,
		{"identity.tokens.issued", "", "true"}:              1,
		{"identity.token.errors", "invalid_grant", "true"}:  1,
		{"identity.token.errors", "invalid_scope", "false"}: 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%v = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
}

// Issue10_U16: the success record has the IDs and no secret.
func TestIssue10_U16_SuccessLog(t *testing.T) {
	e := newExchangeEnv(t)
	in := e.withAgent(e.in(t), agent1)
	res, err := e.cmd.Execute(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	out := e.log.String()
	for _, want := range []string{"identity.token.exchange", "client.id=helpdesk", "user_id=" + user1, "agent_id=" + agent1,
		"audience=mail", "scope=mail:message:read", "jti=exchanged-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("log has no %q: %s", want, out)
		}
	}
	for _, secret := range []string{in.SubjectToken, in.Assertion, res.AccessToken} {
		if strings.Contains(out, secret) {
			t.Errorf("the log has a token")
		}
	}
	// A failure record has no actor value.
	e.log.Reset()
	bad := e.withAgent(e.in(t), agent2)
	_, _ = e.cmd.Execute(ctx, bad)
	if strings.Contains(e.log.String(), agent2) || strings.Contains(e.log.String(), bad.SubjectToken) {
		t.Errorf("the failure log has a secret: %s", e.log.String())
	}
}

// Issue10_U17: userinfo refuses a token with act and a token of a service
// client. It accepts a code flow token.
func TestIssue10_U17_Userinfo(t *testing.T) {
	e := newExchangeEnv(t)
	n := 0
	oidc, err := commands.NewOIDC(commands.OIDCDeps{
		Issuer: issuer, Clients: e.clients, Users: e.users, UserRoles: e.roles,
		Keys: keySet{t: t, f: e.fixture, key: tokensigner.Key{KID: "sig-1", Private: e.sign}}, Signer: jose.Signer{}, Verifier: jose.Verifier{},
		Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	_ = n
	if err != nil {
		t.Fatal(err)
	}
	flow := e.subject(t, nil)
	res, err := oidc.GetUserInfo(ctx, commands.UserInfo{AccessToken: flow})
	if err != nil || res.Subject != user1 || res.Email != "one@example.com" {
		t.Fatalf("code flow token: %+v, %v", res, err)
	}
	for _, actor := range []string{"", agent1} {
		in := e.in(t)
		if actor != "" {
			in = e.withAgent(in, actor)
		}
		ex, err := e.cmd.Execute(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oidc.GetUserInfo(ctx, commands.UserInfo{AccessToken: ex.AccessToken}); !errors.Is(err, commands.ErrInvalidToken) {
			t.Errorf("exchanged token (actor %q): error = %v, want ErrInvalidToken", actor, err)
		}
	}
	withAct := e.subject(t, func(c map[string]any) { c["act"] = map[string]any{"sub": agent1} })
	if _, err := oidc.GetUserInfo(ctx, commands.UserInfo{AccessToken: withAct}); !errors.Is(err, commands.ErrInvalidToken) {
		t.Errorf("token with act: error = %v", err)
	}
	svc := e.subject(t, func(c map[string]any) { c["client_id"] = "helpdesk" })
	if _, err := oidc.GetUserInfo(ctx, commands.UserInfo{AccessToken: svc}); !errors.Is(err, commands.ErrInvalidToken) {
		t.Errorf("token of a service client: error = %v", err)
	}
}
