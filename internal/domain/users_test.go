package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// U1: the password policy counts characters after the normalization.
func TestU1_PasswordPolicy(t *testing.T) {
	cases := map[int]error{
		11:  domain.ErrPasswordTooShort,
		12:  nil,
		128: nil,
		129: domain.ErrPasswordTooLong,
	}
	for n, want := range cases {
		if err := domain.CheckPassword(strings.Repeat("a", n)); !errors.Is(err, want) {
			t.Fatalf("%d characters: err = %v, want %v", n, err, want)
		}
	}
	// 12 characters count by code point, not by byte.
	if err := domain.CheckPassword(strings.Repeat("é", 12)); err != nil {
		t.Fatalf("12 two-byte characters: %v", err)
	}
}

// U5: return_to keeps a local path and drops everything else.
func TestU5_ReturnTo(t *testing.T) {
	cases := map[string]struct {
		want string
		ok   bool
	}{
		"/a":                    {"/a", true},
		"/a?b=c":                {"/a?b=c", true},
		"//evil.example":        {},
		"https://evil.example":  {},
		`/\evil`:                {},
		"/%09/evil.example":     {},
		"/%0A/evil.example":     {},
		"/%5Cevil.example":      {},
		"/a\tb":                 {},
		"":                      {},
		"evil.example":          {},
		"/%2F%2Fevil.example":   {},
		"javascript:alert(1)":   {},
		"/a#frag":               {"/a", true},
		"/a?next=https://x.com": {"/a?next=https://x.com", true},
	}
	for in, c := range cases {
		got, ok := domain.SafeReturnTo(in)
		if ok != c.ok || got != c.want {
			t.Errorf("SafeReturnTo(%q) = %q, %v; want %q, %v", in, got, ok, c.want, c.ok)
		}
	}
}

// U11: the email rules.
func TestU11_Email(t *testing.T) {
	if got, err := domain.NormalizeEmail("  Bob@Example.com "); err != nil || got != "bob@example.com" {
		t.Fatalf("trim and lower: %q, %v", got, err)
	}
	if _, err := domain.NormalizeEmail("a@b"); err != nil {
		t.Fatalf("a@b: %v", err)
	}
	long := strings.Repeat("a", 255-len("@b.co")) + "@b.co"
	for _, bad := range []string{"no-at", "a@b@c", `"Bob" <bob@example.com>`, "<bob@example.com>", long, "", "a b@example.com"} {
		if _, err := domain.NormalizeEmail(bad); !errors.Is(err, domain.ErrInvalidEmail) {
			t.Errorf("NormalizeEmail(%q) = %v, want an error", bad, err)
		}
	}
	exact := strings.Repeat("a", 254-len("@b.co")) + "@b.co"
	if _, err := domain.NormalizeEmail(exact); err != nil {
		t.Errorf("254 characters: %v", err)
	}
}

func TestCheckName(t *testing.T) {
	if got, err := domain.CheckName("  Ada Lovelace "); err != nil || got != "Ada Lovelace" {
		t.Fatalf("name: %q, %v", got, err)
	}
	for _, bad := range []string{"", "   ", "a\nb", strings.Repeat("x", 201)} {
		if _, err := domain.CheckName(bad); !errors.Is(err, domain.ErrInvalidName) {
			t.Errorf("CheckName(%q) = %v", bad, err)
		}
	}
}

func TestSecretHash(t *testing.T) {
	v, h, err := domain.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 43 || h != domain.HashSecret(v) || h == v {
		t.Fatalf("value %q, hash %q", v, h)
	}
	v2, _, _ := domain.NewSecret()
	if v == v2 {
		t.Fatal("two secrets must differ")
	}
}
