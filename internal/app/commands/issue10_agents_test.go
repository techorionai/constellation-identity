package commands_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// roleManifests knows the roles of the test.
type roleManifests struct {
	fakeManifests
}

func (r *roleManifests) Role(_ context.Context, ref domain.RoleRef) (domain.Role, error) {
	if ref == roleMailAgent || ref == roleMailUser {
		return domain.Role{}, nil
	}
	return domain.Role{}, manifests.ErrNotFound
}

type agentEnv struct {
	admin  *commands.Admin
	agents *mock.Agents
	aroles *mock.AgentRoles
	log    *bytes.Buffer
}

func newAgentEnv(t *testing.T) *agentEnv {
	t.Helper()
	f := newFixture(t)
	e := &agentEnv{agents: mock.NewAgents(), aroles: mock.NewAgentRoles(), log: &bytes.Buffer{}}
	e.aroles.Perms[roleMailAgent] = []string{"mail:message:read"}
	e.admin = commands.NewAdmin(commands.AdminDeps{
		Clients: f.clients, Agents: e.agents, AgentRoles: e.aroles, Manifests: &roleManifests{},
		Log: slog.New(slog.NewTextHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now: func() time.Time { return now },
	})
	return e
}

// Test ID map. The scope of each agent operation (U13b) is a rule of the
// OpenAPI contract. The generated router enforces it, so only the integration
// test TestIssue10Integration/I2a_errors in internal/services checks it. The
// discovery document with 4 grant types (U14) has its tests in
// internal/handlers/http/server_test.go (TestU10_Discovery) and
// internal/handlers/http/apitokens_test.go.

// Issue10_U13: an agent needs an existing service client. A disabled service
// client is allowed.
func TestIssue10_U13_CreateAgent(t *testing.T) {
	e := newAgentEnv(t)
	_, err := e.admin.CreateAgent(ctx, "actor", "A1", "web")
	if problemCode(err) != "client_not_service" {
		t.Errorf("public client: %v", err)
	}
	_, err = e.admin.CreateAgent(ctx, "actor", "A2", "nobody")
	if problemCode(err) != "client_not_found" {
		t.Errorf("unknown client: %v", err)
	}
	a, err := e.admin.CreateAgent(ctx, "actor", "A3", "off")
	if err != nil || !a.Enabled || a.ClientID != "off" || !uuidLike(a.ID) {
		t.Errorf("disabled service client: %+v, %v", a, err)
	}
	if _, err := e.admin.CreateAgent(ctx, "actor", "A3", "helpdesk"); problemCode(err) != "agent_name_taken" {
		t.Errorf("same name: %v", err)
	}
	if _, err := e.admin.CreateAgent(ctx, "actor", "a3", "helpdesk"); err != nil {
		t.Errorf("the name is case-sensitive: %v", err)
	}
}

func uuidLike(s string) bool { return len(s) == 36 && strings.Count(s, "-") == 4 }

// Issue10_U13a: the agent name rules.
func TestIssue10_U13a_Names(t *testing.T) {
	e := newAgentEnv(t)
	for name, ok := range map[string]bool{
		strings.Repeat("a", 100): true,
		strings.Repeat("é", 100): true,
		strings.Repeat("a", 101): false,
		strings.Repeat("é", 101): false,
		"":                       false,
		"   ":                    false,
		"bad\x00name":            false,
		"bad\nname":              false,
		"bad\xffname":            false,
		"  padded  ":             true,
	} {
		a, err := e.admin.CreateAgent(ctx, "actor", name, "helpdesk")
		if ok && err != nil {
			t.Errorf("%q: %v", name, err)
		}
		if !ok && err == nil {
			t.Errorf("%q: want an error", name)
		}
		if name == "  padded  " && a.Name != "padded" {
			t.Errorf("stored name = %q", a.Name)
		}
	}
}

// Issue10_U13c: an agent ID that is not a UUID gives agent_not_found, with no
// query.
func TestIssue10_U13c_BadID(t *testing.T) {
	e := newAgentEnv(t)
	name := "n"
	enabled := true
	ref := roleMailAgent
	checks := map[string]error{}
	_, checks["get"] = e.admin.GetAgent(ctx, "x")
	_, checks["update"] = e.admin.UpdateAgent(ctx, "actor", "x", &name, &enabled)
	_, checks["list roles"] = e.admin.ListAgentRoles(ctx, "x", commands.ListPage{})
	_, checks["assign"] = e.admin.AssignAgentRole(ctx, "actor", "x", ref)
	checks["remove"] = e.admin.RemoveAgentRole(ctx, "actor", "x", ref)
	for op, err := range checks {
		if problemCode(err) != "agent_not_found" {
			t.Errorf("%s: %v", op, err)
		}
	}
	if e.agents.GetCalls != 0 {
		t.Errorf("repository calls = %d", e.agents.GetCalls)
	}
}

// Issue10_U13d: update.
func TestIssue10_U13d_Update(t *testing.T) {
	e := newAgentEnv(t)
	one, _ := e.admin.CreateAgent(ctx, "actor", "One", "helpdesk")
	two, _ := e.admin.CreateAgent(ctx, "actor", "Two", "helpdesk")
	got, err := e.admin.UpdateAgent(ctx, "actor", one.ID, nil, nil)
	if err != nil || got != one {
		t.Errorf("empty body: %+v, %v", got, err)
	}
	if strings.Contains(e.log.String(), "Agents_update") {
		t.Error("an empty change must not write a change record")
	}
	taken := "Two"
	if _, err := e.admin.UpdateAgent(ctx, "actor", one.ID, &taken, nil); problemCode(err) != "agent_name_taken" {
		t.Errorf("rename to another name: %v", err)
	}
	own := "One"
	if _, err := e.admin.UpdateAgent(ctx, "actor", one.ID, &own, nil); err != nil {
		t.Errorf("rename to the own name: %v", err)
	}
	off := false
	got, err = e.admin.UpdateAgent(ctx, "actor", two.ID, nil, &off)
	if err != nil || got.Enabled {
		t.Errorf("disable: %+v, %v", got, err)
	}
	bad := "  "
	if _, err := e.admin.UpdateAgent(ctx, "actor", two.ID, &bad, nil); err == nil {
		t.Error("an empty name must fail")
	}
}

// Issue10_U13e: the role operations.
func TestIssue10_U13e_Roles(t *testing.T) {
	e := newAgentEnv(t)
	a, _ := e.admin.CreateAgent(ctx, "actor", "One", "helpdesk")
	for i := 0; i < 2; i++ {
		got, err := e.admin.AssignAgentRole(ctx, "actor", a.ID, roleMailAgent)
		if err != nil || got.Role != roleMailAgent || got.Source != domain.AssignmentAPI || got.Pending {
			t.Fatalf("assign %d: %+v, %v", i, got, err)
		}
	}
	if _, err := e.admin.AssignAgentRole(ctx, "actor", a.ID, roleMailGone); problemCode(err) != "role_unknown" {
		t.Errorf("unknown role: %v", err)
	}
	unknownAgent := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if _, err := e.admin.AssignAgentRole(ctx, "actor", unknownAgent, roleMailGone); problemCode(err) != "agent_not_found" {
		t.Errorf("unknown agent and unknown role: %v", err)
	}
	if err := e.admin.RemoveAgentRole(ctx, "actor", a.ID, roleMailGone); err != nil {
		t.Errorf("remove a missing role: %v", err)
	}
	if err := e.admin.RemoveAgentRole(ctx, "actor", unknownAgent, roleMailAgent); problemCode(err) != "agent_not_found" {
		t.Errorf("remove on an unknown agent: %v", err)
	}
	// A role that left the manifest is pending in the list.
	delete(e.aroles.Perms, roleMailAgent)
	p, err := e.admin.ListAgentRoles(ctx, a.ID, commands.ListPage{})
	if err != nil || len(p.Items) != 1 || !p.Items[0].Pending {
		t.Errorf("list: %+v, %v", p, err)
	}
	if err := e.admin.RemoveAgentRole(ctx, "actor", a.ID, roleMailAgent); err != nil {
		t.Errorf("remove: %v", err)
	}
}

// Issue10_U13f: one change record for each change, with no secret.
func TestIssue10_U13f_Log(t *testing.T) {
	e := newAgentEnv(t)
	a, _ := e.admin.CreateAgent(ctx, "actor-1", "One", "helpdesk")
	name := "Renamed"
	_, _ = e.admin.UpdateAgent(ctx, "actor-1", a.ID, &name, nil)
	_, _ = e.admin.AssignAgentRole(ctx, "actor-1", a.ID, roleMailAgent)
	_ = e.admin.RemoveAgentRole(ctx, "actor-1", a.ID, roleMailAgent)
	out := e.log.String()
	for _, op := range []string{"Agents_create", "Agents_update", "AgentRoles_assign", "AgentRoles_remove"} {
		if n := strings.Count(out, "operation="+op); n != 1 {
			t.Errorf("%s records = %d, want 1\n%s", op, n, out)
		}
	}
	if strings.Count(out, "target_id="+a.ID) != 4 || strings.Count(out, "actor_id=actor-1") != 4 || strings.Count(out, "identity.admin.change") < 4 {
		t.Errorf("records = %s", out)
	}
}
