package domain_test

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

func demoManifest() domain.Manifest {
	return domain.Manifest{
		App: "helpdesk",
		Permissions: []domain.PermissionDef{
			{Key: "helpdesk:ticket:read", Description: "Read tickets."},
			{Key: "helpdesk:ticket:write", Description: "Write tickets."},
		},
		Roles: []domain.RoleDef{
			{Key: "agent", Name: "Agent", Description: "An agent.", Permissions: []string{"helpdesk:ticket:read", "helpdesk:ticket:write"}},
		},
	}
}

func codesAndFields(errs []domain.FieldError) [][2]string {
	var out [][2]string
	for _, e := range errs {
		out = append(out, [2]string{e.Code, e.Field})
	}
	return out
}

// Issue2_U1: a valid manifest has no errors.
func TestIssue2_U1_ValidManifest(t *testing.T) {
	if errs := domain.CheckManifest(demoManifest()); len(errs) != 0 {
		t.Fatalf("errors = %v", errs)
	}
}

// Issue2_U2: a permission key of another app.
func TestIssue2_U2_PermissionAppMismatch(t *testing.T) {
	m := demoManifest()
	m.Permissions[0].Key = "email:message:send"
	m.Roles[0].Permissions = nil
	got := codesAndFields(domain.CheckManifest(m))
	want := [][2]string{{domain.CodePermissionAppMismatch, "/permissions/0/key"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("errors = %v, want %v", got, want)
	}
}

// Issue2_U3: a role permission that is not in the manifest.
func TestIssue2_U3_RolePermissionUnknown(t *testing.T) {
	m := demoManifest()
	m.Roles[0].Permissions = []string{"helpdesk:ticket:read", "helpdesk:ticket:delete"}
	got := codesAndFields(domain.CheckManifest(m))
	want := [][2]string{{domain.CodeRolePermissionUnknown, "/defaultRoles/0/permissions/1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("errors = %v, want %v", got, want)
	}
}

// Issue2_U4: a duplicate permission key and a duplicate role key.
func TestIssue2_U4_DuplicateKeys(t *testing.T) {
	m := demoManifest()
	m.Permissions = append(m.Permissions, domain.PermissionDef{Key: "helpdesk:ticket:read", Description: "Again."})
	m.Roles = append(m.Roles, domain.RoleDef{Key: "agent", Name: "Agent 2", Description: "Again.", Permissions: []string{}})
	got := codesAndFields(domain.CheckManifest(m))
	want := [][2]string{
		{domain.CodeDuplicateKey, "/permissions/2/key"},
		{domain.CodeDuplicateKey, "/defaultRoles/1/key"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("errors = %v, want %v", got, want)
	}
}

// Issue2_U5: three errors are all in one result.
func TestIssue2_U5_AllErrors(t *testing.T) {
	m := demoManifest()
	m.Permissions[0].Key = "email:message:send"
	m.Roles[0].Permissions = []string{"helpdesk:ticket:write", "helpdesk:ticket:delete"}
	m.Permissions = append(m.Permissions, domain.PermissionDef{Key: "helpdesk:ticket:write", Description: "Again."})
	errs := domain.CheckManifest(m)
	if len(errs) != 3 {
		t.Fatalf("errors = %v, want 3", errs)
	}
	codes := []string{errs[0].Code, errs[1].Code, errs[2].Code}
	for _, want := range []string{domain.CodePermissionAppMismatch, domain.CodeRolePermissionUnknown, domain.CodeDuplicateKey} {
		if !slices.Contains(codes, want) {
			t.Fatalf("codes = %v, want %s", codes, want)
		}
	}
}

// Issue2_U5a: the order of the permissions does not change the hash.
func TestIssue2_U5a_CanonicalHash(t *testing.T) {
	a := demoManifest()
	b := demoManifest()
	slices.Reverse(b.Permissions)
	slices.Reverse(b.Roles[0].Permissions)
	if a.Hash() != b.Hash() {
		t.Fatal("the hash depends on the order")
	}
	b.Permissions[0].Description = "Changed."
	if a.Hash() == b.Hash() {
		t.Fatal("the hash does not depend on a description")
	}
	if len(a.Hash()) != 64 {
		t.Fatalf("hash = %q", a.Hash())
	}
}

// Issue2_U5b: a manifest for the app identity, and the other app mismatches.
func TestIssue2_U5b_ManifestAppMismatch(t *testing.T) {
	id := domain.Manifest{App: "identity"}
	if fe := domain.CheckManifestApp("identity", "identity", id); fe == nil || fe.Code != domain.CodeManifestAppMismatch {
		t.Fatalf("identity: %v", fe)
	}
	m := demoManifest()
	cases := []struct {
		name, path, caller string
	}{
		{"path is not the manifest app", "other", "other"},
		{"caller is another app", "helpdesk", "other"},
		{"caller is not a service client", "helpdesk", ""},
	}
	for _, c := range cases {
		if fe := domain.CheckManifestApp(c.path, c.caller, m); fe == nil || fe.Code != domain.CodeManifestAppMismatch {
			t.Errorf("%s: %v", c.name, fe)
		}
	}
	if fe := domain.CheckManifestApp("helpdesk", "helpdesk", m); fe != nil {
		t.Fatalf("matching apps: %v", fe)
	}
}

// The permission identity:admin is valid. It has two segments.
func TestIssue2_AdminPermissionKey(t *testing.T) {
	for key, want := range map[string]bool{
		"identity:admin": true, "helpdesk:admin": false, "helpdesk:ticket:read": true,
		"identity:admin:x": true, "Identity:admin": false, "": false,
	} {
		if got := domain.ValidPermissionKey(key); got != want {
			t.Errorf("ValidPermissionKey(%q) = %v, want %v", key, got, want)
		}
	}
}

// Issue2_U6: a scope of another app.
func TestIssue2_U6_ScopeOfAnotherApp(t *testing.T) {
	granted := []string{"email:message:send", "helpdesk:ticket:read"}
	if _, err := domain.GrantScopes("email", "email:message:send helpdesk:ticket:read", granted); err == nil {
		t.Fatal("a scope of another app passed")
	}
	got, err := domain.GrantScopes("email", "email:message:send email:message:send", granted)
	if err != nil || !reflect.DeepEqual(got, []string{"email:message:send"}) {
		t.Fatalf("scopes = %v, err = %v", got, err)
	}
}

// Issue2_U7: a scope that the roles do not grant. Issue2_U7a: a pending
// assignment grants nothing, so its permission is not in the granted list.
func TestIssue2_U7_ScopeNotGranted(t *testing.T) {
	if _, err := domain.GrantScopes("demo", "demo:ticket:write", []string{"demo:ticket:read"}); err == nil {
		t.Fatal("a scope that is not granted passed")
	}
	if _, err := domain.GrantScopes("demo", "demo:ticket:read", nil); err == nil {
		t.Fatal("a scope passed with no granted scope")
	}
}

// Issue2_U8: no scope.
func TestIssue2_U8_NoScope(t *testing.T) {
	for _, scope := range []string{"", "   "} {
		if _, err := domain.GrantScopes("demo", scope, []string{"demo:ticket:read"}); err == nil {
			t.Fatalf("scope %q passed", scope)
		}
	}
}

// Issue2_U9: the claims of a service token match AccessTokenClaims.
func TestIssue2_U9_TokenClaims(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := domain.ServiceToken{
		Issuer: "https://id.example.com", Audience: "demo", ClientID: "helpdesk",
		Scopes: []string{"demo:ticket:read", "demo:ticket:write"}, Now: now, JTI: "id-1",
	}.Claims()
	want := map[string]any{
		"iss": "https://id.example.com", "sub": "helpdesk", "aud": "demo",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
		"jti": "id-1", "client_id": "helpdesk",
		"scope": "demo:ticket:read demo:ticket:write", "principal_type": "service",
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("claims = %v", c)
	}
	if domain.AccessTokenType != "at+jwt" {
		t.Fatalf("typ = %q", domain.AccessTokenType)
	}
}

func TestIssue2_RoleRef(t *testing.T) {
	ref, err := domain.ParseRoleRef("helpdesk:agent_admin")
	if err != nil || ref.App != "helpdesk" || ref.Role != "agent_admin" || ref.String() != "helpdesk:agent_admin" {
		t.Fatalf("ref = %v, err = %v", ref, err)
	}
	for _, bad := range []string{"", "helpdesk", "helpdesk:", ":agent", "a:b:c", "Helpdesk:agent", "helpdesk:Agent"} {
		if _, err := domain.ParseRoleRef(bad); err == nil {
			t.Errorf("ParseRoleRef(%q) passed", bad)
		}
	}
}
