package testserver

import (
	"regexp"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPCode computes the TOTP code of a base32 secret at a time. Use the time of
// the test clock of the server.
func TOTPCode(t testing.TB, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatalf("testserver: totp code: %v", err)
	}
	return c
}

var (
	secretPattern = regexp.MustCompile(`<code>([A-Z2-7]{16,})</code>`)
	codesPattern  = regexp.MustCompile(`<li><code>([A-Z2-7]{5}-[A-Z2-7]{5})</code>`)
)

// SetupSecretOf reads the base32 secret from the body of the TOTP setup page.
func SetupSecretOf(t testing.TB, body []byte) string {
	t.Helper()
	m := secretPattern.FindSubmatch(body)
	if m == nil {
		t.Fatalf("testserver: no TOTP secret in the page")
	}
	return string(m[1])
}

// RecoveryCodesOf reads the recovery codes from the body of a page.
func RecoveryCodesOf(t testing.TB, body []byte) []string {
	t.Helper()
	var out []string
	for _, m := range codesPattern.FindAllSubmatch(body, -1) {
		out = append(out, string(m[1]))
	}
	return out
}
