package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func signToken(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign([]byte(`{"iss":"x","tid":"y"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// R6, R16: a token with an unknown kid, or with a wrong signature and a known
// kid, must not make a read of the JWKS each time.
func TestReview_R6_R16_KeySetReads(t *testing.T) {
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		k := jose.JSONWebKey{Key: &good.PublicKey, KeyID: "known", Algorithm: "RS256", Use: "sig"}
		raw, _ := k.MarshalJSON()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []json.RawMessage{raw}})
	}))
	defer srv.Close()
	var mu sync.Mutex
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	ks := &msKeySet{url: srv.URL, client: srv.Client(), now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}

	// R16: a wrong signature with a known kid makes no read after the first.
	bad := signToken(t, other, "known")
	for i := 0; i < 5; i++ {
		if _, err := ks.VerifySignature(context.Background(), bad); err == nil {
			t.Fatal("a wrong signature must fail")
		}
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("reads after 5 bad signatures = %d, want 1", got)
	}
	// R6: an unknown kid makes at most one read in a minute.
	unknown := signToken(t, other, "unknown")
	for i := 0; i < 5; i++ {
		if _, err := ks.VerifySignature(context.Background(), unknown); err == nil {
			t.Fatal("an unknown kid must fail")
		}
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("reads after 5 unknown kids = %d, want 1", got)
	}
	// After a minute one read is allowed. A new key shows up in it.
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	if _, err := ks.VerifySignature(context.Background(), unknown); err == nil {
		t.Fatal("an unknown kid must fail")
	}
	if got := reads.Load(); got != 2 {
		t.Fatalf("reads after the minute = %d, want 2", got)
	}
	// A good token works with no read.
	if _, err := ks.VerifySignature(context.Background(), signToken(t, good, "known")); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != 2 {
		t.Fatalf("reads = %d, want 2", got)
	}
}

// R6: a slow read does not block a call that finds the keys in memory.
func TestReview_R6_NoLockDuringRead(t *testing.T) {
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var slow atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if slow.Load() {
			<-release
		}
		k := jose.JSONWebKey{Key: &good.PublicKey, KeyID: "known", Algorithm: "RS256", Use: "sig"}
		raw, _ := k.MarshalJSON()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []json.RawMessage{raw}})
	}))
	defer srv.Close()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	ks := &msKeySet{url: srv.URL, client: srv.Client(), now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	if _, err := ks.VerifySignature(context.Background(), signToken(t, good, "known")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	slow.Store(true)
	done := make(chan struct{})
	go func() {
		_, _ = ks.VerifySignature(context.Background(), signToken(t, good, "unknown-kid"))
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	ok := make(chan error, 1)
	go func() {
		_, err := ks.VerifySignature(context.Background(), signToken(t, good, "known"))
		ok <- err
	}()
	select {
	case err := <-ok:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a call with a known key waits for the read")
	}
	close(release)
	<-done
}
