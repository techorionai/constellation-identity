package commands_test

import (
	"bytes"
	"fmt"
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

const (
	user1 = "11111111-1111-4111-8111-111111111111"
	user2 = "22222222-2222-4222-8222-222222222222"
)

var (
	roleHelpdesk = domain.RoleRef{App: "helpdesk", Role: "agent"}
	roleEmail    = domain.RoleRef{App: "email", Role: "sender"}
)

// tokenEnv is the setup of the API token tests. User 1 is active and has the
// roles helpdesk:agent and email:sender. The implicit role gives
// identity:api_token:manage_own.
type tokenEnv struct {
	*env
	api *mock.APITokens
	log *bytes.Buffer
	max int
}

func newTokenEnv() *tokenEnv {
	e := newEnv()
	e.addUser(user1, "one@example.com", domain.UserActive, "right password 1")
	e.addUser(user2, "two@example.com", domain.UserActive, "right password 1")
	e.roles.Perms[domain.UserRole] = []string{"identity:api_token:manage_own"}
	e.roles.Perms[roleHelpdesk] = []string{"helpdesk:ticket:read", "helpdesk:ticket:write"}
	e.roles.Perms[roleEmail] = []string{"email:message:send"}
	e.roles.Rows[user1] = []domain.RoleRef{roleHelpdesk, roleEmail}
	return &tokenEnv{env: e, api: mock.NewAPITokens(e.users), log: &bytes.Buffer{}, max: 5}
}

func (e *tokenEnv) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (e *tokenEnv) cmd() *commands.APITokens {
	return commands.NewAPITokens(commands.APITokensDeps{
		Tokens: e.api, Users: e.users, UserRoles: e.roles, Tx: mock.Tx{}, Log: e.logger(), Now: e.clock,
		Settings: commands.APITokenSettings{DefaultTTLDays: 90, MaxTTLDays: 365, MaxPerUser: e.max},
	})
}

func (e *tokenEnv) create(c *commands.APITokens, user, name, scope string, days *int32) (commands.CreatedAPIToken, error) {
	return c.Create(ctx, commands.CreateAPIToken{UserID: user, Name: name, Scope: scope, ExpiresInDays: days})
}

func isInvalidInput(err error) bool {
	_, isValidation := apperrors.AsValidationError(err)
	_, isProblem := apperrors.AsProblem(err)
	return err != nil && !isValidation && !isProblem && apperrors.CodeOf(err) == apperrors.InvalidInput
}

func int32p(n int32) *int32 { return &n }

// Issue9_U2: the rules of the name.
func TestIssue9_U2_Name(t *testing.T) {
	e := newTokenEnv()
	c := e.cmd()
	for name, want := range map[string]bool{
		"":                                     false,
		"   ":                                  false,
		"a":                                    true,
		strings.Repeat("a", 100):               true,
		strings.Repeat("a", 101):               false,
		"  " + strings.Repeat("é", 100) + "  ": true,
	} {
		_, err := e.create(c, user1, name, "helpdesk:ticket:read", nil)
		if want && err != nil || !want && !isInvalidInput(err) {
			t.Errorf("name of %d bytes: want ok = %v, err = %v", len(name), want, err)
		}
	}
}

// Issue9_U3: the rules of expiresInDays.
func TestIssue9_U3_ExpiresInDays(t *testing.T) {
	e := newTokenEnv()
	e.max = 50
	c := e.cmd()
	res, err := e.create(c, user1, "default", "helpdesk:ticket:read", nil)
	if err != nil || !res.Token.ExpiresAt.Equal(e.now.AddDate(0, 0, 90)) || !res.Token.CreatedAt.Equal(e.now) {
		t.Fatalf("default: %+v, %v", res.Token, err)
	}
	for _, days := range []int32{1, 365} {
		res, err := e.create(c, user1, "ok", "helpdesk:ticket:read", int32p(days))
		if err != nil || !res.Token.ExpiresAt.Equal(e.now.AddDate(0, 0, int(days))) {
			t.Fatalf("%d days: %+v, %v", days, res.Token, err)
		}
	}
	for _, days := range []int32{0, -1, 366} {
		if _, err := e.create(c, user1, "bad", "helpdesk:ticket:read", int32p(days)); !isInvalidInput(err) {
			t.Fatalf("%d days: err = %v, want invalid input", days, err)
		}
	}
}

func fieldsOf(t *testing.T, err error) []domain.FieldError {
	t.Helper()
	ve, ok := apperrors.AsValidationError(err)
	if !ok {
		t.Fatalf("err = %v, want a validation error", err)
	}
	return ve.Fields
}

// Issue9_U4: a scope that the user does not have gives 422 scope_not_granted,
// with one field error for each key.
func TestIssue9_U4_ScopeNotGranted(t *testing.T) {
	e := newTokenEnv()
	c := e.cmd()
	_, err := e.create(c, user1, "t", "billing:invoice:read", nil)
	f := fieldsOf(t, err)
	if len(f) != 1 || f[0].Code != "scope_not_granted" || f[0].Field != "/scope" || !strings.Contains(f[0].Message, "billing:invoice:read") {
		t.Fatalf("fields = %+v", f)
	}
	_, err = e.create(c, user1, "t", "helpdesk:ticket:read billing:invoice:read billing:invoice:write", nil)
	f = fieldsOf(t, err)
	if len(f) != 2 || f[0].Field != "/scope" || f[1].Field != "/scope" ||
		!strings.Contains(f[0].Message, "billing:invoice:read") || !strings.Contains(f[1].Message, "billing:invoice:write") {
		t.Fatalf("two keys: fields = %+v", f)
	}
	if len(e.api.Rows) != 0 {
		t.Fatal("a refused create must not make a row")
	}
}

// Issue9_U4a: a scope with a wrong syntax gives 400.
func TestIssue9_U4a_ScopeSyntax(t *testing.T) {
	e := newTokenEnv()
	c := e.cmd()
	for _, scope := range []string{"openid helpdesk:ticket:read", "offline_access", "", "   ", "not a key", "helpdesk:ticket", "Helpdesk:ticket:read"} {
		if _, err := e.create(c, user1, "t", scope, nil); !isInvalidInput(err) {
			t.Errorf("scope %q: err = %v, want invalid input", scope, err)
		}
	}
}

// Issue9_U4b: a key of the app identity gives 422 scope_not_granted, also if the
// user has the permission.
func TestIssue9_U4b_IdentityKeys(t *testing.T) {
	e := newTokenEnv()
	e.roles.Perms[domain.AdminRole] = []string{domain.AdminPermission}
	e.roles.Rows[user1] = append(e.roles.Rows[user1], domain.AdminRole)
	c := e.cmd()
	for _, scope := range []string{"identity:admin", "identity:api_token:manage_own", "helpdesk:ticket:read identity:admin"} {
		_, err := e.create(c, user1, "t", scope, nil)
		f := fieldsOf(t, err)
		if len(f) != 1 || f[0].Code != "scope_not_granted" || !strings.Contains(f[0].Message, "identity:") {
			t.Errorf("scope %q: fields = %+v", scope, f)
		}
	}
	if len(e.api.Rows) != 0 {
		t.Fatal("no row must exist")
	}
}

// Issue9_U4c: a user who is not active cannot create a token. No row exists.
func TestIssue9_U4c_UserNotActive(t *testing.T) {
	for _, status := range []domain.UserStatus{domain.UserDisabled, domain.UserInvited} {
		e := newTokenEnv()
		u := e.users.Rows[user1]
		u.Status = status
		e.users.Rows[user1] = u
		_, err := e.create(e.cmd(), user1, "t", "helpdesk:ticket:read", nil)
		if pe, ok := apperrors.AsProblem(err); !ok || pe.Status != 403 || pe.Code != "user_token_required" {
			t.Errorf("%s: err = %v", status, err)
		}
		if len(e.api.Rows) != 0 {
			t.Errorf("%s: a row exists", status)
		}
	}
	// A user that does not exist gets the same answer.
	e := newTokenEnv()
	if _, err := e.create(e.cmd(), user2[:35]+"9", "t", "helpdesk:ticket:read", nil); problemCode(err) != "user_token_required" {
		t.Errorf("unknown user: err = %v", err)
	}
}

func isLimit(err error) bool {
	pe, ok := apperrors.AsProblem(err)
	return ok && pe.Status == 422 && pe.Code == "token_limit"
}

// Issue9_U5: the limit of active tokens. A revoked token and an expired token
// do not count.
func TestIssue9_U5_ActiveLimit(t *testing.T) {
	e := newTokenEnv()
	e.max = 3
	c := e.cmd()
	var first commands.CreatedAPIToken
	for i := range 3 {
		res, err := e.create(c, user1, fmt.Sprint("t", i), "helpdesk:ticket:read", nil)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = res
		}
	}
	if _, err := e.create(c, user1, "over", "helpdesk:ticket:read", nil); !isLimit(err) {
		t.Fatalf("err = %v, want token_limit", err)
	}
	// The limit is for each user.
	if _, err := e.create(c, user2, "other user", "email:message:send", nil); fieldsOf(t, err)[0].Code != "scope_not_granted" {
		t.Fatalf("user 2: err = %v", err)
	}
	if err := c.Revoke(ctx, user1, first.Token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.create(c, user1, "after revoke", "helpdesk:ticket:read", nil); err != nil {
		t.Fatalf("after a revoke: %v", err)
	}
	// An expired token does not count either.
	e.now = e.now.AddDate(0, 0, 91)
	if _, err := e.create(c, user1, "after expiry", "helpdesk:ticket:read", nil); err != nil {
		t.Fatalf("after the expiry: %v", err)
	}
}

// Issue9_U5a: the limit of all rows is 10 times the limit of active tokens.
func TestIssue9_U5a_TotalLimit(t *testing.T) {
	e := newTokenEnv()
	e.max = 2
	c := e.cmd()
	revoked := e.now
	for i := range 19 {
		e.api.Rows[fmt.Sprint("hash", i)] = domain.APIToken{ID: fmt.Sprint("id", i), UserID: user1, CreatedAt: e.now, ExpiresAt: e.now.Add(time.Hour), RevokedAt: &revoked}
	}
	if _, err := e.create(c, user1, "row 20", "helpdesk:ticket:read", nil); err != nil {
		t.Fatalf("19 rows: %v", err)
	}
	// The user has 20 rows and 1 active token. The active limit is not reached.
	if n, _ := e.api.CountActive(ctx, user1, e.now); n != 1 {
		t.Fatalf("active = %d", n)
	}
	if _, err := e.create(c, user1, "row 21", "helpdesk:ticket:read", nil); !isLimit(err) {
		t.Fatalf("20 rows: err = %v, want token_limit", err)
	}
}

// Issue9_U13: a self revoke of a token of another user, of an unknown ID, and of
// an ID that is not a UUID gives 404 api_token_not_found.
func TestIssue9_U13_SelfRevokeNotFound(t *testing.T) {
	e := newTokenEnv()
	c := e.cmd()
	res, err := e.create(c, user1, "t", "helpdesk:ticket:read", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{
		"other user's token": res.Token.ID,
		"unknown":            "33333333-3333-4333-8333-333333333333",
		"not a UUID":         "not-a-uuid",
	} {
		err := c.Revoke(ctx, user2, id)
		if pe, ok := apperrors.AsProblem(err); !ok || pe.Status != 404 || pe.Code != "api_token_not_found" {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for _, t2 := range e.api.Rows {
		if t2.RevokedAt != nil {
			t.Fatal("a token of another user was revoked")
		}
	}
	// A second revoke of the same token gives no error.
	if err := c.Revoke(ctx, user1, res.Token.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(ctx, user1, res.Token.ID); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
}

// Issue9_List: the list is newest first, and the pages follow each other. The
// admin list gives user_not_found for an unknown user and a bad ID.
func TestIssue9_ListPages(t *testing.T) {
	e := newTokenEnv()
	e.max = 10
	c := e.cmd()
	var ids []string
	for i := range 5 {
		e.now = e.now.Add(time.Minute)
		res, err := e.create(c, user1, fmt.Sprint("t", i), "helpdesk:ticket:read", nil)
		if err != nil {
			t.Fatal(err)
		}
		ids = append([]string{res.Token.ID}, ids...)
	}
	var got []string
	size := int32(2)
	token := ""
	for range 5 {
		p, err := c.ListForUser(ctx, user1, commands.ListPage{Size: &size, Token: token})
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range p.Items {
			got = append(got, x.ID)
		}
		if token = p.Next; token == "" {
			break
		}
	}
	if !slices.Equal(got, ids) {
		t.Fatalf("order = %v, want %v", got, ids)
	}
	for _, id := range []string{"33333333-3333-4333-8333-333333333333", "not-a-uuid"} {
		_, err := c.ListForUser(ctx, id, commands.ListPage{})
		if pe, ok := apperrors.AsProblem(err); !ok || pe.Status != 404 || pe.Code != "user_not_found" {
			t.Errorf("user %q: err = %v", id, err)
		}
	}
	if _, err := c.List(ctx, user1, commands.ListPage{Token: "bad"}); !isInvalidInput(err) {
		t.Errorf("bad page token: err = %v", err)
	}
}

// Issue9_Admin: the admin revokes a token of any user. An unknown ID and an ID
// that is not a UUID give 404 api_token_not_found.
func TestIssue9_AdminRevoke(t *testing.T) {
	e := newTokenEnv()
	c := e.cmd()
	res, err := e.create(c, user1, "t", "helpdesk:ticket:read", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AdminRevoke(ctx, "admin-1", res.Token.ID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.log.String(), "operation=api_token.revoke") || !strings.Contains(e.log.String(), "actor_id=admin-1") {
		t.Fatalf("log = %s", e.log)
	}
	for _, id := range []string{"33333333-3333-4333-8333-333333333333", "x"} {
		if pe, ok := apperrors.AsProblem(c.AdminRevoke(ctx, "admin-1", id)); !ok || pe.Code != "api_token_not_found" {
			t.Errorf("id %q", id)
		}
	}
}

// Issue9_U19: the log records of a self revoke and of the disable of a user.
// They have no token value and no hash.
func TestIssue9_U19_LogRecords(t *testing.T) {
	e := newTokenEnv()
	c := e.cmd()
	a, err := e.create(c, user1, "a", "helpdesk:ticket:read", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.create(c, user1, "b", "helpdesk:ticket:read", nil)
	if err != nil {
		t.Fatal(err)
	}
	third, err := e.create(c, user1, "c", "helpdesk:ticket:read", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(ctx, user1, third.Token.ID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.log.String(), "operation=revoke token_id="+third.Token.ID) ||
		!strings.Contains(e.log.String(), "operation=create token_id="+a.Token.ID) {
		t.Fatalf("log = %s", e.log)
	}
	// The admin disables user 1. Two tokens are active.
	e.roles.Perms[domain.AdminRole] = []string{domain.AdminPermission}
	e.roles.Rows[user2] = []domain.RoleRef{domain.AdminRole}
	admin := commands.NewAdmin(commands.AdminDeps{
		Users: e.users, UserRoles: e.roles, Sessions: e.sessions, Tokens: e.tokens, APITokens: e.api,
		Lock: noLock{}, Tx: mock.Tx{}, Log: e.logger(), Now: e.clock,
	})
	disabled := true
	if _, err := admin.UpdateUser(ctx, user2, user1, nil, &disabled); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.log.String(), "operation=Users_update") || !strings.Contains(e.log.String(), "api_tokens_revoked=2") {
		t.Fatalf("log = %s", e.log)
	}
	for _, x := range e.api.Rows {
		if x.RevokedAt == nil {
			t.Fatalf("token %s is not revoked", x.Name)
		}
	}
	// A later enable does not restore the tokens.
	enabled := false
	if _, err := admin.UpdateUser(ctx, user2, user1, nil, &enabled); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.api.CountActive(ctx, user1, e.now); n != 0 {
		t.Fatalf("active tokens after the enable = %d", n)
	}
	for hash, x := range e.api.Rows {
		if strings.Contains(e.log.String(), hash) {
			t.Fatalf("the log has the hash of %s", x.Name)
		}
	}
	for _, v := range []string{a.Value, b.Value, third.Value} {
		if strings.Contains(e.log.String(), v) || strings.Contains(e.log.String(), strings.TrimPrefix(v, "cpat_")) {
			t.Fatal("the log has a token value")
		}
	}
}

func rolesOf(items []domain.RoleAssignment) []string {
	var out []string
	for _, x := range items {
		out = append(out, x.Role.String()+"/"+string(x.Source))
	}
	return out
}

func adminWithRoles(e *tokenEnv, rows ...domain.RoleRef) *commands.Admin {
	e.roles.Rows[user2] = rows
	for _, r := range rows {
		if _, ok := e.roles.Perms[r]; !ok {
			e.roles.Perms[r] = []string{"x:y:z"}
		}
	}
	return commands.NewAdmin(commands.AdminDeps{
		Users: e.users, UserRoles: e.roles, Sessions: e.sessions, Tokens: e.tokens, APITokens: e.api,
		Lock: noLock{}, Tx: mock.Tx{}, Log: e.logger(), Now: e.clock,
	})
}

// Issue9_U17: the list of the roles of a user has identity:user one time, with
// the source config, in the correct page.
func TestIssue9_U17_ListUserRoles(t *testing.T) {
	e := newTokenEnv()
	// A user with no roles.
	a := adminWithRoles(e)
	p, err := a.ListUserRoles(ctx, user2, commands.ListPage{})
	if err != nil || !slices.Equal(rolesOf(p.Items), []string{"identity:user/config"}) || p.Next != "" {
		t.Fatalf("no roles: %v, %v", rolesOf(p.Items), err)
	}
	// Roles on both sides of identity:user, in order of app and role.
	around := []domain.RoleRef{
		{App: "email", Role: "sender"}, {App: "identity", Role: "admin"}, {App: "identity", Role: "zeta"}, {App: "zzz", Role: "last"},
	}
	a = adminWithRoles(e, around...)
	want := []string{"email:sender/api", "identity:admin/api", "identity:user/config", "identity:zeta/api", "zzz:last/api"}
	for size := int32(1); size <= 5; size++ {
		var got []string
		token := ""
		for range 10 {
			p, err := a.ListUserRoles(ctx, user2, commands.ListPage{Size: &size, Token: token})
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Items) > int(size) {
				t.Fatalf("size %d: page has %d items", size, len(p.Items))
			}
			got = append(got, rolesOf(p.Items)...)
			if token = p.Next; token == "" {
				break
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("size %d: roles = %v, want %v", size, got, want)
		}
	}
	// A page border: identity:user is the last item of page 1 (size 3), and the
	// first item of page 2 (size 2).
	three, two := int32(3), int32(2)
	p, _ = a.ListUserRoles(ctx, user2, commands.ListPage{Size: &three})
	if last := rolesOf(p.Items); last[len(last)-1] != "identity:user/config" || p.Next == "" {
		t.Fatalf("size 3, page 1 = %v", last)
	}
	p, _ = a.ListUserRoles(ctx, user2, commands.ListPage{Size: &two})
	p, _ = a.ListUserRoles(ctx, user2, commands.ListPage{Size: &two, Token: p.Next})
	if first := rolesOf(p.Items); first[0] != "identity:user/config" {
		t.Fatalf("size 2, page 2 = %v", first)
	}
	// A stored row with the same role does not show a second time.
	a = adminWithRoles(e, domain.UserRole)
	p, _ = a.ListUserRoles(ctx, user2, commands.ListPage{})
	if !slices.Equal(rolesOf(p.Items), []string{"identity:user/config"}) {
		t.Fatalf("a row for the implicit role: %v", rolesOf(p.Items))
	}
}

// Issue9_U18: assign gives 200 with the source config and writes no row.
// Remove gives no error and changes nothing.
func TestIssue9_U18_AssignRemoveImplicit(t *testing.T) {
	e := newTokenEnv()
	a := adminWithRoles(e)
	got, err := a.AssignUserRole(ctx, user1, user2, domain.UserRole)
	if err != nil || got.Role != domain.UserRole || got.Source != domain.AssignmentConfig {
		t.Fatalf("assign: %+v, %v", got, err)
	}
	if len(e.roles.Rows[user2]) != 0 {
		t.Fatalf("assign wrote a row: %v", e.roles.Rows[user2])
	}
	if err := a.RemoveUserRole(ctx, user1, user2, domain.UserRole); err != nil {
		t.Fatalf("remove: %v", err)
	}
	p, _ := a.ListUserRoles(ctx, user2, commands.ListPage{})
	if !slices.Equal(rolesOf(p.Items), []string{"identity:user/config"}) {
		t.Fatalf("list = %v", rolesOf(p.Items))
	}
	// The user must exist.
	if _, err := a.AssignUserRole(ctx, user1, "99999999-9999-4999-8999-999999999999", domain.UserRole); apperrors.CodeOf(err) != apperrors.NotFound {
		t.Fatalf("assign to an unknown user: %v", err)
	}
	if err := a.RemoveUserRole(ctx, user1, "99999999-9999-4999-8999-999999999999", domain.UserRole); apperrors.CodeOf(err) != apperrors.NotFound {
		t.Fatalf("remove from an unknown user: %v", err)
	}
}

// Issue9_U16: a user with the status active and no roles has the permission of
// the implicit role. A user who is invited or disabled does not have it.
func TestIssue9_U16_ImplicitPermissions(t *testing.T) {
	e := newTokenEnv()
	e.roles.Rows[user2] = nil
	for status, want := range map[domain.UserStatus]bool{domain.UserActive: true, domain.UserInvited: false, domain.UserDisabled: false} {
		got, err := e.roles.GrantedPermissions(ctx, user2, domain.ImplicitUserRoles(status)...)
		if err != nil || slices.Contains(got, "identity:api_token:manage_own") != want {
			t.Errorf("%s: permissions = %v, %v", status, got, err)
		}
	}
}
