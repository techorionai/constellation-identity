package domain_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Issue9_U1: the token has the prefix and 43 characters. 1000 tokens differ.
func TestIssue9_U1_TokenFormat(t *testing.T) {
	seen := map[string]bool{}
	hashes := map[string]bool{}
	for range 1000 {
		value, hash, err := domain.NewAPIToken()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(value, "cpat_") || len(value) != len("cpat_")+43 {
			t.Fatalf("value = %q", value)
		}
		if parsed, ok := domain.ParseAPIToken(value); !ok || parsed != hash {
			t.Fatalf("the parser does not accept the value %q", value)
		}
		seen[value], hashes[hash] = true, true
	}
	if len(seen) != 1000 || len(hashes) != 1000 {
		t.Fatalf("different values = %d, different hashes = %d", len(seen), len(hashes))
	}
}

// Issue9_U7 (format part): the strict parser refuses each bad value.
func TestIssue9_U7_ParseAPIToken(t *testing.T) {
	good, _, err := domain.NewAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimPrefix(good, "cpat_")
	for name, value := range map[string]string{
		"no prefix":       secret,
		"empty":           "",
		"other prefix":    "cpas_" + secret,
		"42 characters":   "cpat_" + secret[:42],
		"44 characters":   "cpat_" + secret + "A",
		"not base64url":   "cpat_" + secret[:42] + "+",
		"space":           "cpat_" + secret[:42] + " ",
		"padding":         "cpat_" + secret[:42] + "=",
		"trailing bits":   "cpat_" + secret[:42] + "B",
		"leading space":   " " + good,
		"trailing space":  good + " ",
		"upper case type": "CPAT_" + secret,
	} {
		if _, ok := domain.ParseAPIToken(value); ok {
			t.Errorf("%s: the parser accepted %q", name, value)
		}
	}
}

// Issue9_U6: the effective scope is the intersection of the stored scope and
// the granted permissions, with the prefix of the caller app. A key of the app
// identity never shows.
func TestIssue9_U6_EffectiveScopes(t *testing.T) {
	stored := []string{"helpdesk:ticket:read", "email:message:send", "helpdesk:ticket:write", "identity:admin", "identity:api_token:manage_own"}
	granted := []string{"helpdesk:ticket:read", "email:message:send", "identity:admin", "identity:api_token:manage_own"}
	if got := domain.EffectiveAPIScopes(stored, granted, "helpdesk"); !slices.Equal(got, []string{"helpdesk:ticket:read"}) {
		t.Errorf("helpdesk = %v", got)
	}
	if got := domain.EffectiveAPIScopes(stored, granted, "email"); !slices.Equal(got, []string{"email:message:send"}) {
		t.Errorf("email = %v", got)
	}
	if got := domain.EffectiveAPIScopes(stored, granted, "billing"); got != nil {
		t.Errorf("billing = %v", got)
	}
	// A stored identity key and the caller app identity: no key in any case.
	if got := domain.EffectiveAPIScopes(stored, granted, "identity"); got != nil {
		t.Errorf("identity = %v", got)
	}
	// A prefix of another app with the same start does not match.
	if got := domain.EffectiveAPIScopes([]string{"helpdesk_two:a:b"}, []string{"helpdesk_two:a:b"}, "helpdesk"); got != nil {
		t.Errorf("similar app = %v", got)
	}
}

// Issue9_U16a: only a user with the status active has the implicit role.
func TestIssue9_U16a_ImplicitRoles(t *testing.T) {
	if got := domain.ImplicitUserRoles(domain.UserActive); !slices.Equal(got, []domain.RoleRef{domain.UserRole}) {
		t.Errorf("active = %v", got)
	}
	for _, s := range []domain.UserStatus{domain.UserInvited, domain.UserDisabled} {
		if got := domain.ImplicitUserRoles(s); len(got) != 0 {
			t.Errorf("%s = %v", s, got)
		}
	}
}
