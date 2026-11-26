package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// maxJWKSBytes is the largest key set that the service reads.
const maxJWKSBytes = 1 << 20

// msKey is a signing key of Microsoft with its issuer property. go-oidc does not
// read this property, and the rule of Microsoft depends on it: a key with a GUID
// issuer is good only for a token with the same iss, and a key with the template
// {tenantid} is good only after the replacement of the template by the tid.
type msKey struct {
	jwk    jose.JSONWebKey
	issuer string
}

// msKeySet is the key set for the Microsoft tenant "organizations". It reads
// the JWKS with the bounded HTTP client of the adapter.
type msKeySet struct {
	url    string
	client *http.Client

	mu   sync.Mutex
	keys []msKey
}

// VerifySignature checks the signature of the token with the key of its kid. If
// the kid is not known, it reads the JWKS again. After a good signature it
// checks the issuer property of the key against the iss and the tid of the
// token.
func (s *msKeySet) VerifySignature(ctx context.Context, rawJWT string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(rawJWT, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, errors.New("the token is not a signed JWT")
	}
	kid := jws.Signatures[0].Header.KeyID
	for _, refresh := range []bool{false, true} {
		keys, err := s.get(ctx, refresh)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if kid != "" && k.jwk.KeyID != kid {
				continue
			}
			payload, err := jws.Verify(&k.jwk)
			if err != nil {
				continue
			}
			var c struct {
				Iss string `json:"iss"`
				Tid string `json:"tid"`
			}
			if err := json.Unmarshal(payload, &c); err != nil {
				return nil, errors.New("the claims are not valid")
			}
			if err := domain.CheckMicrosoftKeyIssuer(k.issuer, c.Iss, c.Tid); err != nil {
				return nil, errors.New("the signing key is not good for the issuer of the token")
			}
			return payload, nil
		}
	}
	return nil, errors.New("no key verifies the token")
}

func (s *msKeySet) get(ctx context.Context, refresh bool) ([]msKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !refresh && len(s.keys) > 0 {
		return s.keys, nil
	}
	keys, err := s.fetch(ctx)
	if err != nil {
		return nil, err
	}
	s.keys = keys
	return keys, nil
}

func (s *msKeySet) fetch(ctx context.Context) ([]msKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read the keys: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read the keys: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return nil, fmt.Errorf("read the keys: %w", err)
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode the keys: %w", err)
	}
	var out []msKey
	for _, raw := range doc.Keys {
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(raw); err != nil || !jwk.Valid() || !jwk.IsPublic() {
			continue
		}
		var extra struct {
			Issuer string `json:"issuer"`
		}
		_ = json.Unmarshal(raw, &extra)
		out = append(out, msKey{jwk: jwk, issuer: extra.Issuer})
	}
	if len(out) == 0 {
		return nil, errors.New("the key set has no usable key")
	}
	return out, nil
}
