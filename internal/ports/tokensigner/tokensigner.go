// Package tokensigner is the port that signs JWTs.
package tokensigner

import "crypto/ecdsa"

// Key is a signing key.
type Key struct {
	KID     string
	Private *ecdsa.PrivateKey
}

// Signer signs a JWT with ES256.
type Signer interface {
	// Sign returns the compact JWS. The header members "alg" and "kid" come
	// from the key. header gives the other members, for example "typ".
	Sign(key Key, claims map[string]any, header map[string]any) (string, error)
}
