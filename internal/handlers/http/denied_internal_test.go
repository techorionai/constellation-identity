package httpapi

import (
	"regexp"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/api/openapi"
)

var actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$`)

// Issue25_U6: each admin route of the scope table has an audit action. An admin
// route is each /v1 route except the routes of the own account (/v1/me). A new
// route with no action gives a test failure, and so does an action with no route.
func TestIssue25_U6_AdminRouteActions(t *testing.T) {
	table, err := NewScopeTable(openapi.Spec)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for pattern := range table {
		if strings.Contains(pattern, " /v1/me") {
			if _, ok := adminActions[pattern]; ok {
				t.Errorf("the account route %q must not have an admin action", pattern)
			}
			continue
		}
		action, ok := adminActions[pattern]
		if !ok {
			t.Errorf("the admin route %q has no audit action", pattern)
			continue
		}
		if !actionPattern.MatchString(action) {
			t.Errorf("%q: the action %q is not valid", pattern, action)
		}
		seen[pattern] = true
	}
	for pattern := range adminActions {
		if !seen[pattern] {
			t.Errorf("the action of %q has no route in the scope table", pattern)
		}
	}
}
