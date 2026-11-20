package config_test

import (
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
)

// Issue2_U11: the roles of a client, also of an app that did not publish.
func TestIssue2_U11_ClientsFileRoles(t *testing.T) {
	j := testJWK(t)
	file := "clients:\n" +
		clientYAML("helpdesk", "helpdesk", "", keyYAML("k1", jwkYAML(j, ""))) +
		"    roles:\n      - demo:agent\n      - unknown_app:reader\n"
	got, err := config.ParseClientsFile([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.RoleRef{{App: "demo", Role: "agent"}, {App: "unknown_app", Role: "reader"}}
	if len(got) != 1 || len(got[0].Roles) != 2 || got[0].Roles[0] != want[0] || got[0].Roles[1] != want[1] {
		t.Fatalf("roles = %+v", got)
	}
}

// Issue2_U11a: a bad role value gives an error that names the client and the
// value.
func TestIssue2_U11a_ClientsFileBadRole(t *testing.T) {
	j := testJWK(t)
	for _, value := range []string{"helpdesk", "demo:", "Demo:agent", "a:b:c"} {
		file := "clients:\n" +
			clientYAML("helpdesk", "helpdesk", "", keyYAML("k1", jwkYAML(j, ""))) +
			"    roles:\n      - \"" + value + "\"\n"
		_, err := config.ParseClientsFile([]byte(file))
		if err == nil || !strings.Contains(err.Error(), `client "helpdesk"`) || !strings.Contains(err.Error(), `"`+value+`"`) {
			t.Errorf("value %q: error = %v", value, err)
		}
	}
	dup := "clients:\n" +
		clientYAML("helpdesk", "helpdesk", "", keyYAML("k1", jwkYAML(j, ""))) +
		"    roles:\n      - demo:agent\n      - demo:agent\n"
	if _, err := config.ParseClientsFile([]byte(dup)); err == nil {
		t.Fatal("a duplicate role passed")
	}
}
