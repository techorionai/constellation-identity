package secrets

import (
	"encoding/json"
	"errors"
	"fmt"

	platformsecrets "github.com/techorionai/constellation-platform-go/secrets"

	"github.com/techorionai/constellation-identity/internal/ports/secretbox"
)

// Sealer seals the TOTP secret of a user with the key ring of the secrets
// package. The sealed value is the envelope in JSON form. The additional data
// is "identity/totp/<user id>".
type Sealer struct {
	ring *platformsecrets.KeyRing
}

var _ secretbox.Sealer = (*Sealer)(nil)

// NewSealer makes the sealer.
func NewSealer(ring *platformsecrets.KeyRing) *Sealer { return &Sealer{ring: ring} }

func totpAAD(userID string) []byte { return []byte("identity/totp/" + userID) }

// Seal seals the secret.
func (s *Sealer) Seal(userID string, plaintext []byte) ([]byte, string, error) {
	env, err := platformsecrets.Seal(s.ring, plaintext, totpAAD(userID))
	if err != nil {
		return nil, "", fmt.Errorf("seal the totp secret: %w", err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		return nil, "", fmt.Errorf("encode the envelope: %w", err)
	}
	return b, env.KeyID, nil
}

// Open opens the secret. A value that does not open wraps
// secretbox.ErrCannotOpen.
func (s *Sealer) Open(userID string, sealed []byte) ([]byte, error) {
	var env platformsecrets.Envelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		return nil, fmt.Errorf("decode the envelope: %w", secretbox.ErrCannotOpen)
	}
	plain, err := platformsecrets.Open(s.ring, env, totpAAD(userID))
	if err != nil {
		if errors.Is(err, platformsecrets.ErrDecrypt) || errors.Is(err, platformsecrets.ErrUnknownKey) ||
			errors.Is(err, platformsecrets.ErrUnsupportedFormat) {
			return nil, fmt.Errorf("open the totp secret: %w", secretbox.ErrCannotOpen)
		}
		return nil, fmt.Errorf("open the totp secret: %w", err)
	}
	return plain, nil
}
