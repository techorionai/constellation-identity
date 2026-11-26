package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

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
	// now is the clock. The default is time.Now.
	now func() time.Time

	mu      sync.Mutex
	keys    []msKey
	fetched time.Time
	// fetchMu lets one call read the JWKS. A call that finds keys in memory does
	// not wait for it (R6).
	fetchMu sync.Mutex
}

// minKeyRefresh is the shortest time between two reads of the JWKS. A token with
// an unknown kid does not make a read before this time passes (R6).
const minKeyRefresh = time.Minute

// VerifySignature checks the signature of the token with the key of its kid. If
// the kid is not known, it reads the JWKS again, at most one time in
// minKeyRefresh. A bad signature with a known kid does not make a read (R16).
// After a good signature it checks the issuer property of the key against the
// iss and the tid of the token.
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
		known := false
		for _, k := range keys {
			if kid != "" && k.jwk.KeyID != kid {
				continue
			}
			known = true
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
		if known {
			// The key of the kid is in memory and the signature is wrong. A read of
			// the JWKS cannot change this result.
			break
		}
	}
	return nil, errors.New("no key verifies the token")
}

func (s *msKeySet) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// get returns the keys. Without refresh, it reads the JWKS only if it has no
// key. With refresh, it reads the JWKS only if the last read is older than
// minKeyRefresh. The mutex is not held during the HTTP call, so a call that finds
// keys in memory does not wait (R6).
func (s *msKeySet) get(ctx context.Context, refresh bool) ([]msKey, error) {
	s.mu.Lock()
	keys, fetched := s.keys, s.fetched
	s.mu.Unlock()
	if len(keys) > 0 && (!refresh || s.clock().Sub(fetched) < minKeyRefresh) {
		return keys, nil
	}
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	s.mu.Lock()
	if len(s.keys) > 0 && !s.fetched.Equal(fetched) {
		// Another call read the JWKS while this call waited.
		keys = s.keys
		s.mu.Unlock()
		return keys, nil
	}
	s.mu.Unlock()
	keys, err := s.fetch(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.keys, s.fetched = keys, s.clock()
	s.mu.Unlock()
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
