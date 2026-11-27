package commands_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/audit"
	platformmock "github.com/techorionai/constellation-platform-go/resources/test/mock"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

var errAuditDown = errors.New("audit down")

// u25 has the commands of the admin flows with one recorder of audit entries.
type u25 struct {
	*env
	ev    *mock.Events
	admin *commands.Admin
}

func newU25() *u25 {
	e := newEnv()
	e.addUser("a", "a@example.com", domain.UserActive, "pw")
	e.addUser("b", "b@example.com", domain.UserActive, "pw")
	e.roles.Perms[domain.AdminRole] = []string{domain.AdminPermission}
	e.roles.Perms[domain.RoleRef{App: "ops", Role: "root"}] = []string{domain.AdminPermission}
	_, _ = e.roles.Assign(ctx, "a", domain.AdminRole, domain.AssignmentAPI)
	_, _ = e.roles.Assign(ctx, "b", domain.RoleRef{App: "ops", Role: "root"}, domain.AssignmentAPI)
	ev := &mock.Events{}
	return &u25{env: e, ev: ev, admin: commands.NewAdmin(commands.AdminDeps{
		Users: e.users, UserRoles: e.roles, Sessions: e.sessions, Tokens: e.tokens, APITokens: mock.NewAPITokens(e.users),
		Lock: noLock{}, Tx: mock.Tx{}, Audit: ev, Now: e.clock, Manifests: &roleManifests{},
	})}
}

func (u *u25) only(t *testing.T, action, targetType, target string) mock.AuditRow {
	t.Helper()
	if len(u.ev.Audits) != 1 {
		t.Fatalf("%s: audits = %+v", action, u.ev.Audits)
	}
	a := u.ev.Audits[0]
	if a.Action != action || a.TargetType != targetType || a.TargetUserID != target || a.Result != "success" {
		t.Fatalf("%s: audit = %+v", action, a)
	}
	return a
}

// auditEvent is the part of the CloudEvent of an audit entry that the tests read.
type auditEvent struct {
	Actor     string `json:"actor"`
	ActorType string `json:"actortype"`
	Data      struct {
		Action  string `json:"action"`
		Result  string `json:"result"`
		Details map[string]any
		Target  *struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"target"`
	} `json:"data"`
}

// lastEvent returns the newest event that the real writer gave to the inserter.
func lastEvent(t *testing.T, ins *platformmock.AuditInserter) auditEvent {
	t.Helper()
	rows := ins.Rows()
	if len(rows) == 0 {
		t.Fatal("the writer wrote no row")
	}
	var e auditEvent
	if err := json.Unmarshal(rows[len(rows)-1].Payload, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

// Issue25_U2: each command of the table writes one entry with the action, the
// target, the result, and the details of the table.
func TestIssue25_U2_Entries(t *testing.T) {
	t.Run("UpdateUser", func(t *testing.T) {
		u := newU25()
		name := "New name"
		if _, err := u.admin.UpdateUser(ctx, "actor", "a", &name, nil); err != nil {
			t.Fatal(err)
		}
		a := u.only(t, commands.ActionUserUpdate, "user", "a")
		if fmt.Sprint(a.Details["fields"]) != "[name]" {
			t.Fatalf("details = %v", a.Details)
		}
	})
	t.Run("UpdateUser with no change writes nothing", func(t *testing.T) {
		u := newU25()
		if _, err := u.admin.UpdateUser(ctx, "actor", "a", nil, nil); err != nil {
			t.Fatal(err)
		}
		if len(u.ev.Audits) != 0 {
			t.Fatalf("audits = %+v", u.ev.Audits)
		}
	})
	t.Run("AssignUserRole writes an entry only when it adds the role (R10)", func(t *testing.T) {
		u := newU25()
		ref := roleMailUser
		for range 2 {
			if _, err := u.admin.AssignUserRole(ctx, "actor", "a", ref); err != nil {
				t.Fatal(err)
			}
		}
		a := u.only(t, commands.ActionUserRoleAssign, "user", "a")
		if a.Details["role"] != ref.String() {
			t.Fatalf("details = %v", a.Details)
		}
	})
	t.Run("RemoveUserRole", func(t *testing.T) {
		u := newU25()
		if err := u.admin.RemoveUserRole(ctx, "actor", "a", domain.AdminRole); err != nil {
			t.Fatal(err)
		}
		a := u.only(t, commands.ActionUserRoleRemove, "user", "a")
		if a.Details["role"] != domain.AdminRole.String() {
			t.Fatalf("details = %v", a.Details)
		}
	})
	t.Run("RevokeUserSessions", func(t *testing.T) {
		u := newU25()
		if err := u.admin.RevokeUserSessions(ctx, "actor", "a"); err != nil {
			t.Fatal(err)
		}
		u.only(t, commands.ActionSessionRevokeAll, "user", "a")
	})
	t.Run("CreateUser and CreateInvite", func(t *testing.T) {
		u := newU25()
		d := u.invites()
		d.Audit = u.ev
		res, err := commands.NewCreateUser(d).Execute(ctx, commands.CreateUser{Email: "new@example.com", Name: "New"})
		if err != nil {
			t.Fatal(err)
		}
		if len(u.ev.Audits) != 2 || u.ev.Audits[0].Action != commands.ActionUserCreate || u.ev.Audits[1].Action != commands.ActionInviteCreate ||
			u.ev.Audits[0].TargetUserID != res.User.ID {
			t.Fatalf("audits = %+v", u.ev.Audits)
		}
		u.ev.Audits = nil
		if _, err := commands.NewCreateInvite(d).Execute(ctx, commands.CreateInvite{UserID: res.User.ID}); err != nil {
			t.Fatal(err)
		}
		u.only(t, commands.ActionInviteCreate, "user", res.User.ID)
	})
	t.Run("SetPassword", func(t *testing.T) {
		u := newU25()
		u.addUser("n", "n@example.com", domain.UserActive, "")
		cmd := commands.NewSetPassword(commands.SetPasswordDeps{Users: u.users, Hasher: u.hasher, Tx: mock.Tx{}, Audit: u.ev, Now: u.clock})
		if err := cmd.Execute(ctx, commands.SetPassword{UserID: "n", Password: "a long new password"}); err != nil {
			t.Fatal(err)
		}
		if a := u.only(t, commands.ActionPasswordSet, "user", "n"); len(a.Details) != 0 {
			t.Fatalf("details = %v", a.Details)
		}
	})
}

// Issue25_U3: an error of the audit writer is the error of the command. The
// change is in the transaction, so the real transactor rolls it back (the
// integration test I4 checks the rollback).
func TestIssue25_U3_WriterError(t *testing.T) {
	u := newU25()
	u.ev.AuditErr = errAuditDown
	name := "New name"
	cases := map[string]func() error{
		"UpdateUser":     func() error { _, err := u.admin.UpdateUser(ctx, "actor", "a", &name, nil); return err },
		"RemoveUserRole": func() error { return u.admin.RemoveUserRole(ctx, "actor", "a", domain.AdminRole) },
		"RevokeAll":      func() error { return u.admin.RevokeUserSessions(ctx, "actor", "a") },
		"CreateUser": func() error {
			d := u.invites()
			d.Audit = u.ev
			_, err := commands.NewCreateUser(d).Execute(ctx, commands.CreateUser{Email: "n@example.com", Name: "N"})
			return err
		},
	}
	for name, run := range cases {
		if err := run(); !errors.Is(err, errAuditDown) {
			t.Errorf("%s: err = %v, want the error of the writer", name, err)
		}
	}
	if len(u.ev.Audits) != 0 {
		t.Fatalf("audits = %+v", u.ev.Audits)
	}
	// A command with no writer gives an error, so no change has no entry.
	_, err := commands.NewAdmin(commands.AdminDeps{Users: u.users, Tx: mock.Tx{}, Lock: noLock{}}).UpdateUser(ctx, "x", "b", &name, nil)
	if !errors.Is(err, commands.ErrNoAuditWriter) {
		t.Errorf("no writer: err = %v, want ErrNoAuditWriter", err)
	}
}

// Issue25_U4: the details of an entry have no password, secret, token, recovery
// code, private key, or email address.
func TestIssue25_U4_NoSecretInDetails(t *testing.T) {
	u := newU25()
	name := "Zed Name"
	_, _ = u.admin.UpdateUser(ctx, "actor", "a", &name, nil)
	_ = u.admin.RemoveUserRole(ctx, "actor", "a", domain.AdminRole)
	d := u.invites()
	d.Audit = u.ev
	_, _ = commands.NewCreateUser(d).Execute(ctx, commands.CreateUser{Email: "new@example.com", Name: "New"})
	if len(u.ev.Audits) < 3 {
		t.Fatalf("audits = %+v", u.ev.Audits)
	}
	for _, a := range u.ev.Audits {
		text := strings.ToLower(fmt.Sprint(a.Details))
		for _, bad := range []string{"@", "password", "secret", "token", "recovery", "private", strings.ToLower(name)} {
			if strings.Contains(text, bad) {
				t.Errorf("%s: details %v has %q", a.Action, a.Details, bad)
			}
		}
	}
}

// Issue25_U5: a reset of the MFA from the command line has no principal. The
// real writer gives the actor identity with the type service. details.origin
// is cli. A reset by an admin with a principal has the admin as the actor and
// no origin.
func TestIssue25_U5_CLIOrigin(t *testing.T) {
	ins := &platformmock.AuditInserter{}
	w, err := audit.New(ins, audit.Config{App: "identity", ClientID: "identity"})
	if err != nil {
		t.Fatal(err)
	}
	m := newMFAEnv(t)
	m.writer = w
	m.build(t)
	m.enable(t, userA, "a@example.com")
	if err := m.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: userA, Operator: true}); err != nil {
		t.Fatal(err)
	}
	e := lastEvent(t, ins)
	if e.Actor != "identity" || e.ActorType != "service" || e.Data.Action != "identity:mfa:reset" || e.Data.Details["origin"] != "cli" ||
		e.Data.Target == nil || e.Data.Target.ID != userA {
		t.Fatalf("cli event = %+v", e)
	}
	m.enable(t, userB, "b@example.com")
	if err := m.cmd.ResetMFA(asUser(adminID), commands.ResetMFA{UserID: userB, Actor: adminID}); err != nil {
		t.Fatal(err)
	}
	e = lastEvent(t, ins)
	if e.Actor != adminID || e.ActorType != "user" || e.Data.Details["origin"] != nil {
		t.Fatalf("admin event = %+v", e)
	}
}

// Issue25_U8: AcceptInvite and CompleteSetup have no principal. The real writer
// gives the actor identity with the type service. details.origin is invite or
// setup. A set password with a one-time link has the origin password_link.
func TestIssue25_U8_FlowOrigin(t *testing.T) {
	ins := &platformmock.AuditInserter{}
	w, err := audit.New(ins, audit.Config{App: "identity", ClientID: "identity"})
	if err != nil {
		t.Fatal(err)
	}
	u := newU25()
	d := u.invites()
	d.Audit = w
	u.addUser("inv", "inv@example.com", domain.UserInvited, "")
	link, err := commands.NewCreateInvite(d).Execute(asUser("a"), commands.CreateInvite{UserID: "inv"})
	if err != nil {
		t.Fatal(err)
	}
	if got := lastEvent(t, ins); got.Actor != "a" || got.ActorType != "user" || got.Data.Action != "identity:invite:create" {
		t.Fatalf("create: %+v", got)
	}
	token := link.URL[strings.Index(link.URL, "?token=")+7:]
	if _, err := commands.NewAcceptInvite(d).Execute(ctx, commands.AcceptInvite{Token: token, Password: "a long new password"}); err != nil {
		t.Fatal(err)
	}
	if got := lastEvent(t, ins); got.Actor != "identity" || got.ActorType != "service" || got.Data.Action != "identity:invite:accept" || got.Data.Details["origin"] != "invite" {
		t.Fatalf("accept: %+v", got)
	}
	e2 := newEnv()
	sd := e2.setup()
	sd.Audit = w
	setup, err := commands.NewEnsureSetupToken(sd).Execute(ctx, commands.EnsureSetupToken{})
	if err != nil {
		t.Fatal(err)
	}
	stoken := setup.Link.URL[strings.Index(setup.Link.URL, "?token=")+7:]
	if _, err := commands.NewCompleteSetup(sd).Execute(ctx, commands.CompleteSetup{Token: stoken, Email: "root@example.com", Name: "Root", Password: "a long new password"}); err != nil {
		t.Fatal(err)
	}
	if got := lastEvent(t, ins); got.Actor != "identity" || got.ActorType != "service" || got.Data.Action != "identity:setup:complete" || got.Data.Details["origin"] != "setup" {
		t.Fatalf("setup: %+v", got)
	}
	e2.addUser("n", "n@example.com", domain.UserActive, "")
	sp := commands.NewSetPassword(commands.SetPasswordDeps{Users: e2.users, Hasher: e2.hasher, Tx: mock.Tx{}, Audit: w, Now: e2.clock})
	if err := sp.Execute(ctx, commands.SetPassword{UserID: "n", Password: "a long new password", Origin: commands.OriginPasswordLink}); err != nil {
		t.Fatal(err)
	}
	if got := lastEvent(t, ins); got.Actor != "identity" || got.ActorType != "service" || got.Data.Details["origin"] != "password_link" {
		t.Fatalf("password link: %+v", got)
	}
}

// Issue25_R12: an update entry lists the fields that changed. A request that
// changes no stored value writes no entry.
func TestIssue25_R12_UpdateChangedFields(t *testing.T) {
	f := newFixture(t)
	ev := &mock.Events{}
	agents, aroles := mock.NewAgents(), mock.NewAgentRoles()
	admin := commands.NewAdmin(commands.AdminDeps{
		Clients: f.clients, Agents: agents, AgentRoles: aroles, Manifests: &roleManifests{}, Tx: mock.Tx{}, Audit: ev,
		Now: func() time.Time { return now },
	})
	ag, err := admin.CreateAgent(ctx, "actor", "Agent R12", "helpdesk")
	if err != nil {
		t.Fatal(err)
	}
	ev.Audits = nil
	same, on, off := "Agent R12", true, false
	if _, err := admin.UpdateAgent(ctx, "actor", ag.ID, &same, &on); err != nil {
		t.Fatal(err)
	}
	if len(ev.Audits) != 0 {
		t.Fatalf("a request with the stored values wrote %+v", ev.Audits)
	}
	if _, err := admin.UpdateAgent(ctx, "actor", ag.ID, &same, &off); err != nil {
		t.Fatal(err)
	}
	if len(ev.Audits) != 1 || fmt.Sprint(ev.Audits[0].Details["fields"]) != "[enabled]" {
		t.Fatalf("audits = %+v", ev.Audits)
	}
}
