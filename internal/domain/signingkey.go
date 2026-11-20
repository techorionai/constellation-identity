// Package domain holds the pure types and rules of the identity service. It
// imports the standard library only.
package domain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// SigningKeyPrefix is the start of the name of each private signing key in the
// secrets store.
const SigningKeyPrefix = "identity/signing-keys/"

// AlgES256 is the only signing algorithm of the service.
const AlgES256 = "ES256"

// KeyState is the state of a signing key.
type KeyState string

// The states of a signing key.
const (
	// KeyPending means the key is in the JWKS and does not sign yet.
	KeyPending KeyState = "pending"
	// KeyActive means the key signs. One key is active.
	KeyActive KeyState = "active"
	// KeyRetired means the key is in the JWKS and does not sign any more.
	KeyRetired KeyState = "retired"
)

// PublicJWK is a public EC P-256 key in JWK format (RFC 7517).
type PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// SigningKey is the data of one signing key. It has no private key.
type SigningKey struct {
	KID            string
	Alg            string
	PublicJWK      PublicJWK
	PrivateKeyName string
	State          KeyState
	CreatedAt      time.Time
	ActivatesAt    time.Time
	RetiredAt      *time.Time
}

// KeyPolicy holds the times of the key lifecycle.
type KeyPolicy struct {
	// RotationPeriod is the age of the active key before rotation.
	RotationPeriod time.Duration
	// PublishDelay is the time that a new key is in the JWKS before it signs.
	PublishDelay time.Duration
	// RetireAfter is the time that a replaced key stays in the JWKS.
	RetireAfter time.Duration
}

// Thumbprint returns the kid of a public key: the first 32 lowercase hex
// characters of the RFC 7638 SHA-256 thumbprint.
func Thumbprint(pub *ecdsa.PublicKey) string {
	// RFC 7638: the members in lexicographic order, with no white space.
	return ThumbprintOfJWK(PublicJWKOf(pub))
}

// ThumbprintOfJWK returns the kid of a public JWK, as Thumbprint does for a
// key. The JWK must be valid. Use ValidatePublicJWK first.
func ThumbprintOfJWK(jwk PublicJWK) string {
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, jwk.Crv, jwk.Kty, jwk.X, jwk.Y)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])[:32]
}

// Validate checks that the row is consistent. The public key must be a P-256
// key on the curve, the RFC 7638 thumbprint of the key must be the kid, the
// members alg and use must be ES256 and sig, and the private key name must be
// PrivateKeyName(kid). The JWKS serves only a row that passes this check.
func (k SigningKey) Validate() error {
	if err := ValidatePublicJWK(k.PublicJWK); err != nil {
		return fmt.Errorf("signing key %s: %w", k.KID, err)
	}
	if got := ThumbprintOfJWK(k.PublicJWK); got != k.KID {
		return fmt.Errorf("signing key %s: the thumbprint of the public key is %s", k.KID, got)
	}
	if k.PublicJWK.Kid != k.KID {
		return fmt.Errorf("signing key %s: the member kid of the public key is not the kid", k.KID)
	}
	if k.Alg != AlgES256 || k.PublicJWK.Alg != AlgES256 {
		return fmt.Errorf("signing key %s: alg must be %s", k.KID, AlgES256)
	}
	if k.PublicJWK.Use != "sig" {
		return fmt.Errorf("signing key %s: use must be sig", k.KID)
	}
	if k.PrivateKeyName != PrivateKeyName(k.KID) {
		return fmt.Errorf("signing key %s: the private key name is not %s", k.KID, PrivateKeyName(k.KID))
	}
	switch k.State {
	case KeyPending, KeyActive, KeyRetired:
	default:
		return fmt.Errorf("signing key %s: unknown state %q", k.KID, k.State)
	}
	return nil
}

// PublicJWKOf returns the JWK of a P-256 public key. The result has no kid.
func PublicJWKOf(pub *ecdsa.PublicKey) PublicJWK {
	// The uncompressed form is 0x04, then X and Y with 32 bytes each.
	raw, err := pub.Bytes()
	if err != nil || len(raw) != 65 {
		return PublicJWK{}
	}
	x, y := raw[1:33], raw[33:]
	return PublicJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}
}

// PrivateKeyName returns the name of the private key in the secrets store.
func PrivateKeyName(kid string) string { return SigningKeyPrefix + kid }

// NewSigningKey makes a key pair and the data row for it. The state is
// KeyPending or KeyActive, as the caller gives it.
func NewSigningKey(now time.Time, state KeyState, activatesAt time.Time) (SigningKey, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return SigningKey{}, nil, fmt.Errorf("generate signing key: %w", err)
	}
	kid := Thumbprint(&priv.PublicKey)
	jwk := PublicJWKOf(&priv.PublicKey)
	jwk.Kid = kid
	jwk.Use = "sig"
	jwk.Alg = AlgES256
	return SigningKey{
		KID:            kid,
		Alg:            AlgES256,
		PublicJWK:      jwk,
		PrivateKeyName: PrivateKeyName(kid),
		State:          state,
		CreatedAt:      now,
		ActivatesAt:    activatesAt,
	}, priv, nil
}

// EncodePrivateKey returns the PKCS #8 PEM text of a private key.
func EncodePrivateKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// DecodePrivateKey reads the PKCS #8 PEM text of a P-256 private key.
func DecodePrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key is not PEM text")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errors.New("private key is not an EC P-256 key")
	}
	return priv, nil
}
