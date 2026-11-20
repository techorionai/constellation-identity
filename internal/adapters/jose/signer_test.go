package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	gojose "github.com/go-jose/go-jose/v4"

	"github.com/techorionai/constellation-identity/internal/adapters/jose"
	"github.com/techorionai/constellation-identity/internal/ports/tokensigner"
)

func TestSignAndVerify(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := tokensigner.Key{KID: "kid1", Private: priv}
	token, err := jose.Signer{}.Sign(key, map[string]any{"sub": "u1"}, map[string]any{"typ": "at+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := gojose.ParseSignedCompact(token, []gojose.SignatureAlgorithm{gojose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := obj.Verify(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil || claims["sub"] != "u1" {
		t.Fatalf("claims = %v, err %v", claims, err)
	}
	h := obj.Signatures[0].Header
	if h.KeyID != "kid1" || h.Algorithm != "ES256" {
		t.Fatalf("header = %+v", h)
	}
	if typ, _ := h.ExtraHeaders[gojose.HeaderType].(string); typ != "at+jwt" {
		t.Fatalf("typ = %v", h.ExtraHeaders)
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key := tokensigner.Key{KID: "k", Private: priv}
	if _, err := (jose.Signer{}).Sign(key, nil, map[string]any{"alg": "none"}); err == nil {
		t.Fatal("alg in the header must fail")
	}
	// R18: only typ is allowed.
	for _, name := range []string{"kid", "jku", "jwk", "x5u", "crit", "b64", "cty"} {
		if _, err := (jose.Signer{}).Sign(key, nil, map[string]any{name: "x"}); err == nil {
			t.Fatalf("header member %s must fail", name)
		}
	}
	if _, err := (jose.Signer{}).Sign(key, nil, map[string]any{"typ": 5}); err == nil {
		t.Fatal("a typ that is not a string must fail")
	}
	if _, err := (jose.Signer{}).Sign(tokensigner.Key{}, nil, nil); err == nil {
		t.Fatal("an empty key must fail")
	}
}
