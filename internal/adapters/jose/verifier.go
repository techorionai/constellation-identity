package jose

import (
	"crypto/ecdsa"
	"encoding/json"
	"math"
	"time"

	gojose "github.com/go-jose/go-jose/v4"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/tokenverifier"
)

// maxTokenLength is the largest token that the verifier reads.
const maxTokenLength = 8192

// Verifier is the adapter of the port tokenverifier on go-jose.
type Verifier struct{}

var _ tokenverifier.Verifier = Verifier{}

// rawClaims reads the claims. The audience can be a string or a list.
type rawClaims struct {
	Iss       string          `json:"iss"`
	Sub       string          `json:"sub"`
	Aud       json.RawMessage `json:"aud"`
	Exp       *float64        `json:"exp"`
	ClientID  string          `json:"client_id"`
	Scope     string          `json:"scope"`
	Principal string          `json:"principal_type"`
	SID       string          `json:"sid"`
}

// Verify checks the ES256 signature with the key that has the kid of the
// header. It does not check the time claims.
func (Verifier) Verify(token string, keys []domain.PublicJWK) (tokenverifier.Claims, error) {
	if token == "" || len(token) > maxTokenLength {
		return tokenverifier.Claims{}, tokenverifier.ErrInvalid
	}
	obj, err := gojose.ParseSignedCompact(token, []gojose.SignatureAlgorithm{gojose.ES256})
	if err != nil || len(obj.Signatures) != 1 {
		return tokenverifier.Claims{}, tokenverifier.ErrInvalid
	}
	h := obj.Signatures[0].Protected
	if h.Algorithm != string(gojose.ES256) || h.KeyID == "" {
		return tokenverifier.Claims{}, tokenverifier.ErrInvalid
	}
	var pub *ecdsa.PublicKey
	for _, k := range keys {
		if k.Kid == h.KeyID {
			pub, _ = publicKey(k)
			break
		}
	}
	if pub == nil {
		return tokenverifier.Claims{}, tokenverifier.ErrInvalid
	}
	payload, err := obj.Verify(pub)
	if err != nil {
		return tokenverifier.Claims{}, tokenverifier.ErrInvalid
	}
	var rc rawClaims
	if err := json.Unmarshal(payload, &rc); err != nil {
		return tokenverifier.Claims{}, tokenverifier.ErrInvalid
	}
	out := tokenverifier.Claims{
		Issuer: rc.Iss, Subject: rc.Sub, ClientID: rc.ClientID, Scope: rc.Scope,
		PrincipalType: rc.Principal, SessionID: rc.SID,
	}
	if typ, ok := h.ExtraHeaders[gojose.HeaderType].(string); ok {
		out.Typ = typ
	}
	if len(rc.Aud) > 0 {
		var one string
		var many []string
		if json.Unmarshal(rc.Aud, &one) == nil {
			out.Audience = []string{one}
		} else if json.Unmarshal(rc.Aud, &many) == nil {
			out.Audience = many
		}
	}
	if rc.Exp != nil && *rc.Exp > 0 && *rc.Exp < math.MaxInt32*4 {
		out.ExpiresAt = time.Unix(int64(*rc.Exp), 0).UTC()
	}
	return out, nil
}
