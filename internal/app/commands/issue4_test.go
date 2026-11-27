package commands_test

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

type noLock struct{}

func (noLock) Lock(context.Context) error { return nil }

func (e *env) admin() *commands.Admin {
	e.roles.Perms[domain.AdminRole] = []string{domain.AdminPermission}
	e.roles.Perms[domain.RoleRef{App: "ops", Role: "root"}] = []string{domain.AdminPermission}
	return commands.NewAdmin(commands.AdminDeps{
		Users: e.users, UserRoles: e.roles, Sessions: e.sessions, Tokens: e.tokens, APITokens: mock.NewAPITokens(e.users), Lock: noLock{}, Tx: mock.Tx{}, Audit: &mock.Events{}, Now: e.clock,
	})
}

func problemCode(err error) string {
	if pe, ok := apperrors.AsProblem(err); ok {
		return pe.Code
	}
	return ""
}

// Issue4_U12: the six cases of the previous session at a login.
func TestIssue4_U12_LoginPreviousSession(t *testing.T) {
	login := func(e *env, prev string, email string) commands.IssuedSession {
		t.Helper()
		got, err := e.login().Execute(ctx, commands.Login{Email: email, Password: "right password 1", IP: "1.1.1.1", PreviousToken: prev})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	setup := func() (*env, commands.IssuedSession) {
		e := newEnv()
		e.addUser("a", "a@example.com", domain.UserActive, "right password 1")
		e.addUser("b", "b@example.com", domain.UserActive, "right password 1")
		return e, login(e, "", "a@example.com")
	}
	// 1. Same user and valid: keep, new auth_time and new cookie value.
	e, first := setup()
	e.now = e.now.Add(time.Minute)
	second := login(e, first.Token, "a@example.com")
	if second.SessionID != first.SessionID || second.Token == first.Token || !second.AuthTime.After(first.AuthTime) {
		t.Fatalf("keep: %+v %+v", first, second)
	}
	row := e.sessions.Rows[first.SessionID]
	if row.RevokedAt != nil || !row.CreatedAt.Equal(first.AuthTime) || !row.AuthTime.Equal(second.AuthTime) || !row.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("session row = %+v", row)
	}
	// 2. Same user and revoked: new session.
	e, first = setup()
	_ = e.sessions.RevokeByTokenHash(ctx, domain.HashSecret(first.Token), e.now)
	if got := login(e, first.Token, "a@example.com"); got.SessionID == first.SessionID {
		t.Fatal("a revoked session must not be kept")
	}
	// 3. Past the idle expiry.
	e, first = setup()
	e.now = e.now.Add(2 * time.Hour)
	if got := login(e, first.Token, "a@example.com"); got.SessionID == first.SessionID || e.sessions.Rows[first.SessionID].RevokedAt == nil {
		t.Fatal("an idle expired session must be revoked and replaced")
	}
	// 4. Past the absolute expiry.
	e, first = setup()
	e.now = e.now.Add(25 * time.Hour)
	if got := login(e, first.Token, "a@example.com"); got.SessionID == first.SessionID {
		t.Fatal("an expired session must be replaced")
	}
	// 5. Different user: revoke and replace.
	e, first = setup()
	got := login(e, first.Token, "b@example.com")
	if got.SessionID == first.SessionID || e.sessions.Rows[first.SessionID].RevokedAt == nil || !got.AuthTime.Equal(e.sessions.Rows[got.SessionID].CreatedAt) {
		t.Fatal("another user must get a new session and the old one ends")
	}
	// 6. No previous session.
	e, _ = setup()
	n := len(e.sessions.Rows)
	login(e, "", "b@example.com")
	login(e, "unknown", "b@example.com")
	if len(e.sessions.Rows) != n+2 {
		t.Fatal("a login with no previous session makes a session")
	}
}

// Issue4_U5: the last admin rule.
func TestIssue4_U5_LastAdmin(t *testing.T) {
	e := newEnv()
	e.addUser("a", "a@example.com", domain.UserActive, "x")
	_, _ = e.roles.Assign(ctx, "a", domain.AdminRole, domain.AssignmentAPI)
	a := e.admin()
	disabled := true
	// The mock transactor does not roll back, so each check has its own data.
	if err := a.RemoveUserRole(ctx, "actor", "a", domain.AdminRole); problemCode(err) != "last_admin" {
		t.Fatalf("role removal: %v", err)
	}
	e = newEnv()
	e.addUser("a", "a@example.com", domain.UserActive, "x")
	_, _ = e.roles.Assign(ctx, "a", domain.AdminRole, domain.AssignmentAPI)
	a = e.admin()
	if _, err := a.UpdateUser(ctx, "actor", "a", nil, &disabled); problemCode(err) != "last_admin" {
		t.Fatalf("disable: %v", err)
	}
	e = newEnv()
	e.addUser("a", "a@example.com", domain.UserActive, "x")
	_, _ = e.roles.Assign(ctx, "a", domain.AdminRole, domain.AssignmentAPI)
	a = e.admin()
	// A second admin makes the change valid.
	e.addUser("b", "b@example.com", domain.UserActive, "x")
	_, _ = e.roles.Assign(ctx, "b", domain.AdminRole, domain.AssignmentAPI)
	if _, err := a.UpdateUser(ctx, "actor", "a", nil, &disabled); err != nil {
		t.Fatalf("disable with a second admin: %v", err)
	}
	if e.users.Rows["a"].Status != domain.UserDisabled {
		t.Fatal("the user must be disabled")
	}
}

// Issue4_U16: the count of the last admin rule.
func TestIssue4_U16_CountHolders(t *testing.T) {
	e := newEnv()
	e.addUser("a", "a@example.com", domain.UserActive, "x")
	e.addUser("p", "p@example.com", domain.UserActive, "x")
	e.addUser("d", "d@example.com", domain.UserDisabled, "x")
	e.addUser("o", "o@example.com", domain.UserActive, "x")
	_, _ = e.roles.Assign(ctx, "a", domain.AdminRole, domain.AssignmentAPI)
	// A pending assignment has no permissions in the mock.
	_, _ = e.roles.Assign(ctx, "p", domain.RoleRef{App: "ghost", Role: "admin"}, domain.AssignmentAPI)
	_, _ = e.roles.Assign(ctx, "d", domain.AdminRole, domain.AssignmentAPI)
	e.admin()
	n, _ := e.roles.CountActiveHolders(ctx, domain.AdminPermission)
	if n != 1 {
		t.Fatalf("holders = %d, want 1 (pending and disabled do not count)", n)
	}
	// A second role that grants identity:admin counts.
	_, _ = e.roles.Assign(ctx, "o", domain.RoleRef{App: "ops", Role: "root"}, domain.AssignmentAPI)
	if n, _ = e.roles.CountActiveHolders(ctx, domain.AdminPermission); n != 2 {
		t.Fatalf("holders = %d, want 2", n)
	}
	// So the first admin can lose the role.
	if err := e.admin().RemoveUserRole(ctx, "actor", "a", domain.AdminRole); err != nil {
		t.Fatalf("role removal with a second holder: %v", err)
	}
}

// Issue4_U8: enable a disabled user.
func TestIssue4_U8_Enable(t *testing.T) {
	e := newEnv()
	e.addUser("n", "n@example.com", domain.UserDisabled, "")
	e.addUser("w", "w@example.com", domain.UserDisabled, "pw")
	enable := false
	a := e.admin()
	if u, err := a.UpdateUser(ctx, "actor", "n", nil, &enable); err != nil || u.Status != domain.UserInvited {
		t.Fatalf("no password: %v %v", u.Status, err)
	}
	if u, err := a.UpdateUser(ctx, "actor", "w", nil, &enable); err != nil || u.Status != domain.UserActive {
		t.Fatalf("with a password: %v %v", u.Status, err)
	}
}

// Issue4_U15: the page token codec and the page size.
func TestIssue4_U15_Paging(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	tok := commands.EncodeTimeCursor(at, "11111111-1111-4111-8111-111111111111")
	cur, err := commands.DecodeTimeCursor(tok)
	if err != nil || !cur.CreatedAt.Equal(at) || cur.ID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("time cursor: %+v %v", cur, err)
	}
	role, err := commands.DecodeRoleCursor(commands.EncodeRoleCursor(domain.RoleRef{App: "demo", Role: "agent"}))
	if err != nil || role.App != "demo" || role.Role != "agent" {
		t.Fatalf("role cursor: %+v %v", role, err)
	}
	for _, bad := range []string{"!!", "e30", "WyJ4Il0", commands.EncodeRoleCursor(domain.RoleRef{App: "demo", Role: "agent"})} {
		if _, err := commands.DecodeTimeCursor(bad); err == nil {
			t.Errorf("time cursor %q must fail", bad)
		}
	}
	if _, err := commands.DecodeRoleCursor(tok); err == nil {
		t.Error("a time cursor is not a role cursor")
	}
	e := newEnv()
	a := e.admin()
	for _, n := range []int32{0, -1, 201} {
		if _, err := a.ListUsers(ctx, commands.ListPage{Size: &n}); apperrors.CodeOf(err) != apperrors.InvalidInput {
			t.Errorf("pageSize %d: %v", n, err)
		}
	}
	for i := 0; i < 5; i++ {
		e.addUser("00000000-0000-4000-8000-00000000000"+strconv.Itoa(i), "u"+strconv.Itoa(i)+"@example.com", domain.UserActive, "x")
	}
	two := int32(2)
	p, err := a.ListUsers(ctx, commands.ListPage{Size: &two})
	if err != nil || len(p.Items) != 2 || p.Next == "" {
		t.Fatalf("page: %+v %v", p, err)
	}
	seen := map[string]bool{}
	token := ""
	for i := 0; i < 5; i++ {
		p, err := a.ListUsers(ctx, commands.ListPage{Size: &two, Token: token})
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range p.Items {
			if seen[u.ID] {
				t.Fatalf("duplicate %s", u.ID)
			}
			seen[u.ID] = true
		}
		if p.Next == "" {
			break
		}
		token = p.Next
	}
	if len(seen) != 5 {
		t.Fatalf("seen = %d", len(seen))
	}
}

// Issue4_U6_U7: client rules.
func TestIssue4_U6_U7_ClientRules(t *testing.T) {
	a := commands.NewAdmin(commands.AdminDeps{Tx: mock.Tx{}, Audit: &mock.Events{}})
	if _, err := a.CreateClient(ctx, "actor", commands.CreateClientInput{Type: domain.ClientTypeService, App: "identity", Name: "S"}); problemCode(err) != "app_reserved" {
		t.Fatalf("app_reserved: %v", err)
	}
	if _, err := a.CreateClient(ctx, "actor", commands.CreateClientInput{Type: domain.ClientTypePublic, App: "demo", Name: "P", JWK: &commands.JWKInput{}}); problemCode(err) != "client_type_unsupported" {
		t.Fatalf("a key on a public client: %v", err)
	}
	if _, err := a.CreateClient(ctx, "actor", commands.CreateClientInput{Type: domain.ClientTypePublic, App: "demo", Name: "P", RedirectURIs: []string{"https://a/cb#x"}}); apperrors.CodeOf(err) == apperrors.Internal {
		if _, ok := apperrors.AsValidationError(err); !ok {
			t.Fatalf("invalid_redirect_uri: %v", err)
		}
	}
	_ = http.StatusOK
}
