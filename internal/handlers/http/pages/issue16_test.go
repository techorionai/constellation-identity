package pages_test

import (
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
)

// U9 of issue 16: the query parameters of the upstream login are redacted. The
// parameters code, state, and nonce were redacted before. id_token,
// error_description, and session_state are new.
func TestIssue16_U9_RedactedParameters(t *testing.T) {
	raw := "code=c1&state=s1&nonce=n1&id_token=i1&error_description=e1&session_state=ss1&purpose=login&iss=https%3A%2F%2Fa"
	got := pages.RedactQuery(raw)
	for _, secret := range []string{"c1", "s1", "n1", "i1", "e1", "ss1"} {
		for _, part := range strings.Split(got, "&") {
			if _, v, _ := strings.Cut(part, "="); v == secret {
				t.Errorf("the value %q is not redacted in %s", secret, got)
			}
		}
	}
	for _, keep := range []string{"purpose=login", "iss=https%3A%2F%2Fa"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q must stay in %s", keep, got)
		}
	}
	if !strings.Contains(pages.RedactURL("/login/oidc/google/callback?"+raw), "state=REDACTED") {
		t.Error("the location is not redacted")
	}
}
