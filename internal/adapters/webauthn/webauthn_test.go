package webauthn_test

import (
	"testing"

	"github.com/techorionai/constellation-identity/internal/adapters/webauthn"
)

// U1 and U2 of issue 15: the RP ID and the origin come from the issuer. U3: an
// IP address gives no RP ID.
func TestIssue15_RelyingParty(t *testing.T) {
	for _, c := range []struct {
		issuer, rpID, origin string
		ok                   bool
	}{
		{"https://id.example.com/auth", "id.example.com", "https://id.example.com", true},
		{"http://localhost:8080", "localhost", "http://localhost:8080", true},
		{"https://id.example.com:8443", "id.example.com", "https://id.example.com:8443", true},
		{"http://127.0.0.1:8080", "", "", false},
		{"http://[::1]:8080", "", "", false},
		{"https://192.0.2.10", "", "", false},
	} {
		rpID, origin, ok := webauthn.RelyingParty(c.issuer)
		if rpID != c.rpID || origin != c.origin || ok != c.ok {
			t.Errorf("%s: got %q %q %v, want %q %q %v", c.issuer, rpID, origin, ok, c.rpID, c.origin, c.ok)
		}
	}
}
