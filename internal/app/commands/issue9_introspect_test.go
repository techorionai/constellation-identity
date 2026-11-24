package commands_test

import (
	"bytes"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// introspectEnv has a client "helpdesk" with a real assertion check, a user with
// roles, and one stored API token.
type introspectEnv struct {
	*fixture
	users *mock.Users
	roles *mock.UserRoles
	api   *mock.APITokens
	cmd   *commands.IntrospectCommand
	log   *bytes.Buffer
	value string
	row   domain.APIToken
}

func newIntrospectEnv(t *testing.T) *introspectEnv {
	t.Helper()
	f := newFixture(t)
	u := mock.NewUsers()
	u.Rows[user1] = domain.User{ID: user1, Email: "one@example.com", Name: "One", Status: domain.UserActive}
	roles := mock.NewUserRoles(u)
	roles.Perms[domain.UserRole] = []string{"identity:api_token:manage_own"}
	roles.Perms[roleHelpdesk] = []string{"helpdesk:ticket:read", "helpdesk:ticket:write"}
	roles.Perms[roleEmail] = []string{"email:message:send"}
	roles.Rows[user1] = []domain.RoleRef{roleHelpdesk, roleEmail}
	api := mock.NewAPITokens(u)
	e := &introspectEnv{fixture: f, users: u, roles: roles, api: api, log: &bytes.Buffer{}}
	value, hash, err := domain.NewAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	e.value = value
	e.row = domain.APIToken{
		ID: "44444444-4444-4444-8444-444444444444", UserID: user1, Name: "t",
		Scope:     []string{"helpdesk:ticket:read", "email:message:send", "identity:admin"},
		CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour),
	}
	api.Rows[hash] = e.row
	cmd, err := commands.NewIntrospect(commands.IntrospectDeps{
		Auth: f.cmd, Tokens: api, UserRoles: roles,
		Log: slog.New(slog.NewTextHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.cmd = cmd
	return e
}

// in makes a valid request for the token of the test.
func (e *introspectEnv) in(t *testing.T) commands.Introspect {
	t.Helper()
	return commands.Introspect{Token: e.value, AssertionType: domain.AssertionType, Assertion: e.assertion(t, nil)}
}

func (e *introspectEnv) hash() string { return domain.HashSecret(e.value) }

func (e *introspectEnv) change(f func(*domain.APIToken)) {
	row := e.api.Rows[e.hash()]
	f(&row)
	e.api.Rows[e.hash()] = row
}

func inactive(t *testing.T, res commands.IntrospectResult, err error) {
	t.Helper()
	if err != nil || res.Active || res.Scope != nil || res.Sub != "" || res.Aud != "" || res.JTI != "" || res.Exp != 0 || res.Iat != 0 {
		t.Fatalf("result = %+v, err = %v, want an inactive result with no other field", res, err)
	}
}

// Issue9_U7: each bad input and each inactive token gives an inactive result
// with no other field. The format cases do not call the repository.
func TestIssue9_U7_Inactive(t *testing.T) {
	e := newIntrospectEnv(t)
	secret := strings.TrimPrefix(e.value, "cpat_")
	for name, token := range map[string]string{
		"empty":         "",
		"no prefix":     secret,
		"513 bytes":     "cpat_" + strings.Repeat("a", 508),
		"42 characters": "cpat_" + secret[:42],
		"44 characters": "cpat_" + secret + "A",
		"not base64url": "cpat_" + secret[:42] + "*",
		"space":         "cpat_" + secret[:42] + " ",
	} {
		in := e.in(t)
		in.Token = token
		before := e.api.Lookups
		res, err := e.cmd.Execute(ctx, in)
		inactive(t, res, err)
		if e.api.Lookups != before {
			t.Errorf("%s: the repository was called", name)
		}
	}
	// A token that the repository does not know.
	other, _, _ := domain.NewAPIToken()
	in := e.in(t)
	in.Token = other
	res, err := e.cmd.Execute(ctx, in)
	inactive(t, res, err)

	revoked := now.Add(-time.Minute)
	for name, change := range map[string]func(){
		"revoked":  func() { e.change(func(r *domain.APIToken) { r.RevokedAt = &revoked }) },
		"expired":  func() { e.change(func(r *domain.APIToken) { r.ExpiresAt = now }) },
		"disabled": func() { e.users.Rows[user1] = domain.User{ID: user1, Status: domain.UserDisabled} },
		"invited":  func() { e.users.Rows[user1] = domain.User{ID: user1, Status: domain.UserInvited} },
		"no scope": func() { e.roles.Rows[user1] = nil },
	} {
		e = newIntrospectEnv(t)
		change()
		res, err := e.cmd.Execute(ctx, e.in(t))
		if err != nil || res.Active {
			t.Errorf("%s: result = %+v, err = %v", name, res, err)
			continue
		}
		inactive(t, res, err)
	}
}

// Issue9_U8: an active token gives all fields. The scope has only keys of the
// caller app.
func TestIssue9_U8_Active(t *testing.T) {
	e := newIntrospectEnv(t)
	res, err := e.cmd.Execute(ctx, e.in(t))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Active || !slices.Equal(res.Scope, []string{"helpdesk:ticket:read"}) || res.Sub != user1 || res.Aud != "helpdesk" ||
		res.JTI != e.row.ID || res.Exp != e.row.ExpiresAt.Unix() || res.Iat != e.row.CreatedAt.Unix() {
		t.Fatalf("result = %+v", res)
	}
	// The permission of the role is current: a removed role removes the scope.
	e.roles.Rows[user1] = []domain.RoleRef{roleEmail}
	res, err = e.cmd.Execute(ctx, e.in(t))
	inactive(t, res, err)
}

func requireOAuth(t *testing.T, err error, code string) {
	t.Helper()
	if oe, ok := apperrors.AsOAuthError(err); !ok || oe.Code != code {
		t.Fatalf("err = %v, want the OAuth error %s", err, code)
	}
}

// Issue9_U9a: a repeated field gives invalid_request.
func TestIssue9_U9a_Repeated(t *testing.T) {
	e := newIntrospectEnv(t)
	in := e.in(t)
	in.RepeatedParameter = true
	_, err := e.cmd.Execute(ctx, in)
	requireOAuth(t, err, apperrors.OAuthInvalidRequest)
}

// Issue9_U9b: a public client gives invalid_client.
func TestIssue9_U9b_PublicClient(t *testing.T) {
	e := newIntrospectEnv(t)
	in := e.in(t)
	in.Assertion = e.assertion(t, func(c map[string]any) { c["iss"], c["sub"] = "web", "web" })
	_, err := e.cmd.Execute(ctx, in)
	requireOAuth(t, err, apperrors.OAuthInvalidClient)
	in = e.in(t)
	in.Assertion = e.assertion(t, func(c map[string]any) { c["iss"], c["sub"] = "unknown", "unknown" })
	_, err = e.cmd.Execute(ctx, in)
	requireOAuth(t, err, apperrors.OAuthInvalidClient)
}

// Issue9_U9c: a bad signature, an expired assertion, and a wrong audience give
// invalid_client.
func TestIssue9_U9c_BadAssertion(t *testing.T) {
	e := newIntrospectEnv(t)
	for name, assertion := range map[string]string{
		"bad signature": e.assertion(t, func(c map[string]any) { c["iss"], c["sub"] = "other", "other" }),
		"expired": e.assertion(t, func(c map[string]any) {
			c["exp"] = now.Add(-time.Hour).Unix()
			c["iat"] = now.Add(-2 * time.Hour).Unix()
		}),
		"wrong audience": e.assertion(t, func(c map[string]any) { c["aud"] = "https://other.example.com" }),
		"not a JWT":      "abc",
	} {
		in := e.in(t)
		in.Assertion = assertion
		_, err := e.cmd.Execute(ctx, in)
		if oe, ok := apperrors.AsOAuthError(err); !ok || oe.Code != apperrors.OAuthInvalidClient {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// Issue9_U9d: a client secret gives invalid_client. Issue9_U9e: a Basic header
// gives invalid_client. The command gets both as SecondAuthentication.
func TestIssue9_U9d_U9e_SecondAuthentication(t *testing.T) {
	e := newIntrospectEnv(t)
	in := e.in(t)
	in.SecondAuthentication = true
	_, err := e.cmd.Execute(ctx, in)
	requireOAuth(t, err, apperrors.OAuthInvalidClient)
}

// Issue9_U9f: a missing or a wrong assertion type and an empty assertion give
// invalid_client. The token endpoint and the client check keep invalid_request.
func TestIssue9_U9f_AssertionFields(t *testing.T) {
	e := newIntrospectEnv(t)
	for name, change := range map[string]func(*commands.Introspect){
		"missing type": func(in *commands.Introspect) { in.AssertionType = "" },
		"wrong type":   func(in *commands.Introspect) { in.AssertionType = "urn:other" },
		"empty":        func(in *commands.Introspect) { in.Assertion = "" },
	} {
		in := e.in(t)
		change(&in)
		_, err := e.cmd.Execute(ctx, in)
		if oe, ok := apperrors.AsOAuthError(err); !ok || oe.Code != apperrors.OAuthInvalidClient {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// The mapping is only in the introspection. The client check keeps its code.
	_, err := e.fixture.cmd.AuthenticateService(ctx, "", "x", "")
	requireOAuth(t, err, apperrors.OAuthInvalidRequest)
	_, err = e.fixture.cmd.Execute(ctx, commands.IssueServiceToken{GrantType: "client_credentials", Audience: "demo", Scope: "demo:ticket:read"})
	requireOAuth(t, err, apperrors.OAuthInvalidRequest)
}

// Issue9_U9g: a failure of the jti store gives temporarily_unavailable.
func TestIssue9_U9g_JTIStoreFails(t *testing.T) {
	e := newIntrospectEnv(t)
	e.jti.err = errors.New("valkey down")
	_, err := e.cmd.Execute(ctx, e.in(t))
	requireOAuth(t, err, apperrors.OAuthTemporarilyUnavailable)
}

// Issue9_U9h: a failure of PostgreSQL during the client authentication gives
// temporarily_unavailable.
func TestIssue9_U9h_ClientStoreFails(t *testing.T) {
	e := newIntrospectEnv(t)
	e.clients.getErr = errors.New("postgres down")
	_, err := e.cmd.Execute(ctx, e.in(t))
	requireOAuth(t, err, apperrors.OAuthTemporarilyUnavailable)
}

// Issue9_U10: an error of the token lookup gives temporarily_unavailable.
func TestIssue9_U10_RepositoryError(t *testing.T) {
	e := newIntrospectEnv(t)
	e.api.GetErr = errors.New("postgres down")
	_, err := e.cmd.Execute(ctx, e.in(t))
	requireOAuth(t, err, apperrors.OAuthTemporarilyUnavailable)
}

// Issue9_U11: an error of the last_used_at update does not change the response.
// The log has one warn record, and the record has no token data.
func TestIssue9_U11_TouchError(t *testing.T) {
	e := newIntrospectEnv(t)
	e.api.TouchErr = errors.New("update failed")
	res, err := e.cmd.Execute(ctx, e.in(t))
	if err != nil || !res.Active {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	log := e.log.String()
	if strings.Count(log, "level=WARN") != 1 || strings.Contains(log, e.value) || strings.Contains(log, e.hash()) || strings.Contains(log, user1) {
		t.Fatalf("log = %s", log)
	}
}

// Issue9_I12 (unit part): the update of last_used_at runs for a token with no
// value, and does not run again in the same hour.
func TestIssue9_LastUsedInterval(t *testing.T) {
	e := newIntrospectEnv(t)
	if _, err := e.cmd.Execute(ctx, e.in(t)); err != nil {
		t.Fatal(err)
	}
	got := e.api.Rows[e.hash()].LastUsedAt
	if got == nil || !got.Equal(now) {
		t.Fatalf("last_used_at = %v", got)
	}
	// The same clock again: the value does not change.
	if _, err := e.cmd.Execute(ctx, e.in(t)); err != nil {
		t.Fatal(err)
	}
	if !e.api.Rows[e.hash()].LastUsedAt.Equal(now) {
		t.Fatal("the value changed inside the hour")
	}
}
