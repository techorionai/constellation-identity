// Package jose is the adapter of the port tokensigner on go-jose.
package jose

import (
	"encoding/json"
	"errors"
	"fmt"

	gojose "github.com/go-jose/go-jose/v4"

	"github.com/techorionai/constellation-identity/internal/ports/tokensigner"
)

// Signer signs JWTs with ES256.
type Signer struct{}

var _ tokensigner.Signer = Signer{}

// Sign returns the compact JWS of the claims. The only header member that the
// caller can set is "typ". Any other member is an error. The key gives "alg"
// and "kid", and members such as "jku", "jwk", "x5u", and "crit" change how a
// verifier finds keys or reads the token.
func (Signer) Sign(key tokensigner.Key, claims map[string]any, header map[string]any) (string, error) {
	if key.Private == nil || key.KID == "" {
		return "", errors.New("sign: the key is not complete")
	}
	opts := (&gojose.SignerOptions{}).WithType("JWT")
	for k, v := range header {
		if k != "typ" {
			return "", fmt.Errorf("sign: header member %q is not allowed", k)
		}
		s, ok := v.(string)
		if !ok {
			return "", errors.New("sign: header member typ must be a string")
		}
		opts = opts.WithType(gojose.ContentType(s))
	}
	jwk := gojose.JSONWebKey{Key: key.Private, KeyID: key.KID, Algorithm: string(gojose.ES256)}
	sig, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.ES256, Key: jwk}, opts)
	if err != nil {
		return "", fmt.Errorf("sign: make signer: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("sign: encode claims: %w", err)
	}
	obj, err := sig.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("sign: serialize: %w", err)
	}
	return out, nil
}
