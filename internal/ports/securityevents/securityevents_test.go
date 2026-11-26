package securityevents_test

import (
	"testing"

	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
)

// U25 of issue 16: the constants of the identity links.
func TestIssue16_U25_Constants(t *testing.T) {
	for got, want := range map[string]string{
		securityevents.ActionIdentityLinkAdd:     "identity:identity_link:add",
		securityevents.ActionIdentityLinkRemove:  "identity:identity_link:remove",
		securityevents.NoticeIdentityLinkAdded:   "identity_link_added",
		securityevents.NoticeIdentityLinkRemoved: "identity_link_removed",
	} {
		if got != want {
			t.Errorf("constant = %q, want %q", got, want)
		}
	}
}
