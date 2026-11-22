// Package tokenverifier is the port that checks the signature of a JWT that
// the service signed.
package tokenverifier

import (
	"errors"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// ErrInvalid means the token has a bad form, a bad signature, an unknown key,
// or an algorithm that is not ES256.
var ErrInvalid = errors.New("the token is not valid")

// Claims are the claims and the header members that the use cases check. The
// verifier does not check the time claims. The use case does.
type Claims struct {
	// Typ is the header member typ.
	Typ           string
	Issuer        string
	Subject       string
	Audience      []string
	ClientID      string
	Scope         string
	PrincipalType string
	SessionID     string
	ExpiresAt     time.Time
}

// Verifier checks the signature with the keys.
type Verifier interface {
	// Verify returns the claims of a token with a valid ES256 signature of one
	// of the keys. It returns ErrInvalid in all other cases.
	Verify(token string, keys []domain.PublicJWK) (Claims, error)
}
