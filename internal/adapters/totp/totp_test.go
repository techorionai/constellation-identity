package totp_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	pqtotp "github.com/pquerna/otp/totp"

	"github.com/techorionai/constellation-identity/internal/adapters/totp"
)

func codeAt(t *testing.T, s totp.Service, secret []byte, at time.Time) string {
	t.Helper()
	c, err := pqtotp.GenerateCodeCustom(s.Base32(secret), at, pqtotp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// U3: a code for the step N, N-1, N+1, and N+2 at the test clock.
func TestU3_StepSkew(t *testing.T) {
	s := totp.New()
	secret, err := s.NewSecret()
	if err != nil || len(secret) != 20 {
		t.Fatalf("secret = %d bytes, %v", len(secret), err)
	}
	now := time.Unix(1_700_000_010, 0).UTC()
	n := now.Unix() / 30
	cases := []struct {
		name string
		at   time.Time
		ok   bool
		step int64
	}{
		{"N", now, true, n},
		{"N-1", now.Add(-30 * time.Second), true, n - 1},
		{"N+1", now.Add(30 * time.Second), true, n + 1},
		{"N+2", now.Add(60 * time.Second), false, 0},
		{"N-2", now.Add(-60 * time.Second), false, 0},
	}
	for _, c := range cases {
		step, ok := s.Check(secret, codeAt(t, s, secret, c.at), now)
		if ok != c.ok || (ok && step != c.step) {
			t.Errorf("%s: step %d ok %v, want step %d ok %v", c.name, step, ok, c.step, c.ok)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "12 456"} {
		if _, ok := s.Check(secret, bad, now); ok {
			t.Errorf("%q must not be good", bad)
		}
	}
}

func TestURIAndQR(t *testing.T) {
	s := totp.New()
	secret, _ := s.NewSecret()
	uri := s.URI("Constellation", "a@example.com", secret)
	for _, want := range []string{"otpauth://totp/", "issuer=Constellation", "algorithm=SHA1", "digits=6", "period=30", "secret=" + s.Base32(secret)} {
		if !strings.Contains(uri, want) {
			t.Errorf("uri %q has no %q", uri, want)
		}
	}
	png, err := s.QRCode(uri)
	if err != nil || !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Fatalf("qr = %d bytes, %v", len(png), err)
	}
}
