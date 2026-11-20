// Package assertion is the port that parses and verifies client assertions.
package assertion

import (
	"errors"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// ErrMalformed means the text is not a compact JWS that the port can read.
var ErrMalformed = errors.New("the assertion is malformed")

// ErrBadSignature means the signature or the claims do not verify.
var ErrBadSignature = errors.New("the assertion signature is not valid")

// Parser reads a client assertion.
type Parser interface {
	// Parse reads the compact JWS. It does not verify the signature.
	Parse(raw string) (Assertion, error)
}

// Assertion is a parsed assertion with a signature that is not verified. The
// values of Algorithm, KeyID, and Subject are not trusted until Verify
// succeeds.
type Assertion interface {
	// Algorithm returns the header member alg.
	Algorithm() string
	// KeyID returns the header member kid.
	KeyID() string
	// Subject returns the claim sub, or an empty string.
	Subject() string
	// Verify checks the ES256 signature with the key and returns the claims.
	Verify(key domain.PublicJWK) (domain.AssertionClaims, error)
}
