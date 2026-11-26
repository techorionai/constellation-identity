package domain_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// U4: the sign count rule of WebAuthn Level 3 section 7.2.
func TestIssue15_U4_SignCountRule(t *testing.T) {
	for _, c := range []struct {
		stored, next uint32
		want         bool
	}{
		{0, 0, true}, {5, 6, true}, {5, 5, false}, {5, 0, false}, {0, 3, true},
	} {
		if got := domain.SignCountAccepted(c.stored, c.next); got != c.want {
			t.Errorf("stored %d new %d: got %v, want %v", c.stored, c.next, got, c.want)
		}
	}
}

// U5: the methods of a login with a passkey.
func TestIssue15_U5_Methods(t *testing.T) {
	if got := domain.MethodsPasskeyLogin(); !slices.Equal(got, []string{"hwk", "user", "mfa"}) {
		t.Errorf("passkey login = %v", got)
	}
	if got := domain.WithSecondFactor(domain.MethodsPassword(), domain.PasskeyFactor(true)...); !slices.Equal(got, []string{"pwd", "hwk", "user", "mfa"}) {
		t.Errorf("password and passkey with UV = %v", got)
	}
	if got := domain.WithSecondFactor(domain.MethodsPassword(), domain.PasskeyFactor(false)...); !slices.Equal(got, []string{"pwd", "hwk", "mfa"}) {
		t.Errorf("password and passkey with no UV = %v", got)
	}
}

// U10: the name rule of the contract v0.6.0.
func TestIssue15_U10_PasskeyName(t *testing.T) {
	valid := []string{
		"a",
		strings.Repeat("a", 64),
		"My key 2",
		strings.Repeat("\u00e9", 64),
		"Cl\u00e9",
		"a b",
		"\u65e5\u672c\u8a9e",
	}
	invalid := []string{
		"",
		strings.Repeat("a", 65),
		strings.Repeat("\u00e9", 65),
		" a",
		"a ",
		" ",
		"a\nb",
		"a\tb",
		"a\u200bb",
		"a\u202eb",
		"a\u2028b",
		"a\u2029b",
		"\u00a0a",
		"a\u00a0",
		"\u3000a",
		"a\x00b",
		"a\x7fb",
		"\xff\xfe",
		"a\u0085b",
		"\ufeffa",
		"a\u00adb",
		strings.Repeat("a", 63) + "\u200b",
	}
	for _, s := range valid {
		if err := domain.ValidatePasskeyName(s); err != nil {
			t.Errorf("%q must be valid: %v", s, err)
		}
	}
	for _, s := range invalid {
		if err := domain.ValidatePasskeyName(s); err == nil {
			t.Errorf("%q must not be valid", s)
		}
	}
}

// U11: a stored passkey is a second factor only when passkeys are on.
func TestIssue15_U11_Enabled(t *testing.T) {
	if !(domain.MFAState{Passkeys: 1, PasskeysOn: true}).Enabled() {
		t.Error("a passkey with passkeys on must enable MFA")
	}
	if (domain.MFAState{Passkeys: 1, PasskeysOn: false}).Enabled() {
		t.Error("a passkey with passkeys off must not enable MFA")
	}
	if !(domain.MFAState{HasTOTP: true}).Enabled() || (domain.MFAState{}).Enabled() {
		t.Error("TOTP enables MFA and the empty state does not")
	}
}
