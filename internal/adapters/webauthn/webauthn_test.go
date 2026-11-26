package webauthn_test

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/techorionai/constellation-identity/internal/adapters/webauthn"
	port "github.com/techorionai/constellation-identity/internal/ports/webauthn"
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

// R3: mapError turns real errors of the library into the errors of the port. The
// test fails if a new version of the library changes the text that the mapping reads.
func TestIssue15_R3_MapError(t *testing.T) {
	const challenge = "challenge"
	clientData := protocol.CollectedClientData{Type: protocol.AssertCeremony, Challenge: challenge, Origin: "https://evil.example"}
	originErr := clientData.Verify(challenge, protocol.AssertCeremony, []string{"https://id.example"}, nil, nil, protocol.TopOriginExplicitVerificationMode, false)

	rpHash := sha256.Sum256([]byte("id.example"))
	otherHash := sha256.Sum256([]byte("evil.example"))
	hashErr := (&protocol.AuthenticatorData{RPIDHash: otherHash[:], Flags: protocol.FlagUserPresent | protocol.FlagUserVerified}).
		Verify(rpHash[:], nil, true, true)
	uvErr := (&protocol.AuthenticatorData{RPIDHash: rpHash[:], Flags: protocol.FlagUserPresent}).
		Verify(rpHash[:], nil, true, true)

	for _, c := range []struct {
		name string
		in   error
		want error
	}{
		{"origin", originErr, port.ErrBadOrigin},
		{"RP ID hash", hashErr, port.ErrBadOrigin},
		{"user verification", uvErr, port.ErrUserVerification},
		{"unknown credential", &protocol.ErrorUnknownCredential{Err: protocol.ErrBadRequest}, port.ErrUnknownCredential},
		{"other", protocol.ErrAssertionSignature, port.ErrBadSignature},
		{"not a library error", errors.New("x"), port.ErrBadSignature},
	} {
		if c.in == nil {
			t.Fatalf("%s: the library gave no error", c.name)
		}
		if got := webauthn.MapError(c.in); !errors.Is(got, c.want) {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
