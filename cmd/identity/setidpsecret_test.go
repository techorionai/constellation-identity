package main

import (
	"bytes"
	"strings"
	"testing"
)

// U8: set-idp-secret gives the exit code 2 for no provider, for a provider that
// is not valid, and for an empty secret on stdin. No call to the database runs
// in these cases, because no variable of the environment is set.
func TestIssue16_U8_SetIdpSecretUsage(t *testing.T) {
	for _, c := range []struct {
		name  string
		args  []string
		stdin string
	}{
		{"no provider", []string{"set-idp-secret"}, "secret\n"},
		{"unknown provider", []string{"set-idp-secret", "okta"}, "secret\n"},
		{"wrong case", []string{"set-idp-secret", "Google"}, "secret\n"},
		{"too many arguments", []string{"set-idp-secret", "google", "extra"}, "secret\n"},
		{"empty stdin", []string{"set-idp-secret", "google"}, ""},
		{"empty line", []string{"set-idp-secret", "google"}, "\n"},
		{"secret too long", []string{"set-idp-secret", "google"}, strings.Repeat("a", maxIdpSecretBytes+1) + "\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			old := stdin
			stdin = strings.NewReader(c.stdin)
			t.Cleanup(func() { stdin = old })
			var out, errOut bytes.Buffer
			if got := run(c.args, &out, &errOut); got != 2 {
				t.Fatalf("exit = %d, want 2 (stderr %q)", got, errOut.String())
			}
			if out.Len() != 0 {
				t.Fatalf("stdout = %q", out.String())
			}
			if strings.Contains(errOut.String(), "secret\n") && c.stdin != "" && strings.Contains(errOut.String(), c.stdin) {
				t.Fatal("the secret must not be in the output")
			}
		})
	}
}

func TestIssue16_ReadSecretLine(t *testing.T) {
	got, err := readSecretLine(strings.NewReader("abc\r\nnext"))
	if err != nil || got != "abc" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = readSecretLine(strings.NewReader("no-newline"))
	if err != nil || got != "no-newline" {
		t.Fatalf("got %q, %v", got, err)
	}
}
