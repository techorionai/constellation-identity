package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	gojose "github.com/go-jose/go-jose/v4"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/assertion"
)

// maxAssertionLength is the largest assertion that the parser reads.
const maxAssertionLength = 8192

// parseAlgs are the algorithms that the parser reads, so that the use case can
// tell the algorithm. Verify accepts ES256 only.
var parseAlgs = []gojose.SignatureAlgorithm{
	gojose.ES256, gojose.ES384, gojose.ES512,
	gojose.RS256, gojose.RS384, gojose.RS512,
	gojose.PS256, gojose.PS384, gojose.PS512,
	gojose.HS256, gojose.HS384, gojose.HS512,
	gojose.EdDSA,
}

// AssertionParser is the adapter of the port assertion on go-jose.
type AssertionParser struct{}

var _ assertion.Parser = AssertionParser{}

// Parse reads a compact JWS with one signature.
func (AssertionParser) Parse(raw string) (assertion.Assertion, error) {
	if raw == "" || len(raw) > maxAssertionLength {
		return nil, assertion.ErrMalformed
	}
	obj, err := gojose.ParseSignedCompact(raw, parseAlgs)
	if err != nil || len(obj.Signatures) != 1 {
		return nil, assertion.ErrMalformed
	}
	a := &parsed{obj: obj, alg: obj.Signatures[0].Header.Algorithm, kid: obj.Signatures[0].Header.KeyID}
	// The payload is not trusted. The use case reads sub only to find the keys.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(obj.UnsafePayloadWithoutVerification(), &m); err != nil || m == nil {
		return nil, assertion.ErrMalformed
	}
	if raw, ok := m["sub"]; ok {
		var sub string
		if err := json.Unmarshal(raw, &sub); err == nil {
			a.sub = sub
		}
	}
	return a, nil
}

type parsed struct {
	obj *gojose.JSONWebSignature
	alg string
	kid string
	sub string
}

func (p *parsed) Algorithm() string { return p.alg }
func (p *parsed) KeyID() string     { return p.kid }
func (p *parsed) Subject() string   { return p.sub }

// Verify checks the ES256 signature and reads the claims. A claim name is
// exact: the decoder of encoding/json would match names without case.
func (p *parsed) Verify(key domain.PublicJWK) (domain.AssertionClaims, error) {
	if p.alg != string(gojose.ES256) {
		return domain.AssertionClaims{}, assertion.ErrBadSignature
	}
	pub, err := publicKey(key)
	if err != nil {
		return domain.AssertionClaims{}, assertion.ErrBadSignature
	}
	payload, err := p.obj.Verify(pub)
	if err != nil {
		return domain.AssertionClaims{}, assertion.ErrBadSignature
	}
	c, err := readClaims(payload)
	if err != nil {
		return domain.AssertionClaims{}, assertion.ErrBadSignature
	}
	return c, nil
}

func publicKey(jwk domain.PublicJWK) (*ecdsa.PublicKey, error) {
	if err := domain.ValidatePublicJWK(jwk); err != nil {
		return nil, err
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, append(x, y...)...))
}

var errClaims = errors.New("the claims are not valid")

func readClaims(payload []byte) (domain.AssertionClaims, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil || m == nil {
		return domain.AssertionClaims{}, errClaims
	}
	var c domain.AssertionClaims
	str := func(name string, dst *string) error {
		raw, ok := m[name]
		if !ok || bytes.Equal(raw, []byte("null")) {
			return nil
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return fmt.Errorf("%s: %w", name, errClaims)
		}
		return nil
	}
	num := func(name string, dst **time.Time) error {
		raw, ok := m[name]
		if !ok || bytes.Equal(raw, []byte("null")) {
			return nil
		}
		var f float64
		if err := json.Unmarshal(raw, &f); err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 253402300799 {
			return fmt.Errorf("%s: %w", name, errClaims)
		}
		t := time.Unix(int64(f), 0).UTC()
		*dst = &t
		return nil
	}
	for _, step := range []func() error{
		func() error { return str("iss", &c.Issuer) },
		func() error { return str("sub", &c.Subject) },
		func() error { return str("jti", &c.JTI) },
		func() error { return num("exp", &c.ExpiresAt) },
		func() error { return num("iat", &c.IssuedAt) },
		func() error { return num("nbf", &c.NotBefore) },
	} {
		if err := step(); err != nil {
			return domain.AssertionClaims{}, err
		}
	}
	if raw, ok := m["aud"]; ok && !bytes.Equal(raw, []byte("null")) {
		var one string
		var many []string
		switch {
		case json.Unmarshal(raw, &one) == nil:
			c.Audience = []string{one}
		case json.Unmarshal(raw, &many) == nil:
			c.Audience = many
		default:
			return domain.AssertionClaims{}, fmt.Errorf("aud: %w", errClaims)
		}
	}
	return c, nil
}
