package securitynotices_test

import (
	"testing"

	"github.com/techorionai/constellation-identity/internal/ports/securitynotices"
)

// U25 of issue 16: the constants of the notices.
func TestIssue16_U25_Constants(t *testing.T) {
	for got, want := range map[string]string{
		securitynotices.NoticeIdentityLinkAdded:   "identity_link_added",
		securitynotices.NoticeIdentityLinkRemoved: "identity_link_removed",
		securitynotices.NoticePasswordSet:         "password_set",
	} {
		if got != want {
			t.Errorf("constant = %q, want %q", got, want)
		}
	}
}
