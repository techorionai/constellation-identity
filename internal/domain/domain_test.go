package domain_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// U6: the kid is the first 32 hex characters of the RFC 7638 thumbprint, and the
// secret name matches the secrets name pattern.
func TestU6_KidAndSecretName(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := domain.PublicJWKOf(&priv.PublicKey)
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, jwk.X, jwk.Y)
	sum := sha256.Sum256([]byte(canonical))
	want := hex.EncodeToString(sum[:])[:32]

	kid := domain.Thumbprint(&priv.PublicKey)
	if kid != want {
		t.Fatalf("kid = %s, want %s", kid, want)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(kid) {
		t.Fatalf("kid %q is not 32 lowercase hex characters", kid)
	}
	name := domain.PrivateKeyName(kid)
	if name != "identity/signing-keys/"+kid {
		t.Fatalf("name = %s", name)
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,199}$`).MatchString(name) {
		t.Fatalf("name %q does not match the secrets pattern", name)
	}
}

func TestNewSigningKeyRoundTrip(t *testing.T) {
	now := time.Now()
	key, priv, err := domain.NewSigningKey(now, domain.KeyActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if key.KID != domain.Thumbprint(&priv.PublicKey) || key.PublicJWK.Kid != key.KID {
		t.Fatal("kid mismatch")
	}
	if err := domain.ValidatePublicJWK(key.PublicJWK); err != nil {
		t.Fatal(err)
	}
	pem, err := domain.EncodePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	back, err := domain.DecodePrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(priv) {
		t.Fatal("decoded key differs")
	}
	if _, err := domain.DecodePrivateKey([]byte("text")); err == nil {
		t.Fatal("want an error for text that is not PEM")
	}
}
