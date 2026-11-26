package oidc_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	adapter "github.com/techorionai/constellation-identity/internal/adapters/oidc"
	"github.com/techorionai/constellation-identity/internal/ports/upstreamidp"
	"github.com/techorionai/constellation-identity/resources/test/oidcprovider"
)

// R5: a key set that does not answer during the check of the ID token is a
// provider error, not a token error. go-oidc wraps the error with %v, so the
// adapter finds the cause with the count of the failed HTTP calls.
func TestReview_R5_KeySetTimeoutIsProviderError(t *testing.T) {
	p := oidcprovider.Start(t)
	c := adapter.New(adapter.Config{
		Issuer: "https://id.example.com", HTTPTimeout: 500 * time.Millisecond, Transport: p.Transport(),
		Google: adapter.ProviderConfig{ClientID: oidcprovider.GoogleClientID, ClientSecret: oidcprovider.GoogleSecret},
	})
	p.Expect(googleLogin(nil))
	ap := params()
	code, iss, _ := authorize(t, c, p, "google", ap)
	p.SetDelay("keys", 3*time.Second)
	_, err := c.Exchange(bg, "google", upstreamidp.ExchangeParams{Code: code, Verifier: ap.Verifier, Nonce: ap.Nonce, Iss: iss})
	if !errors.Is(err, upstreamidp.ErrProvider) || errors.Is(err, upstreamidp.ErrToken) {
		t.Fatalf("err = %v, want a provider error", err)
	}
	// A bad token with a working key set stays a token error.
	p.SetDelay("keys", 0)
	if _, err := exchange(t, c, p, googleLogin(func(l *oidcprovider.Login) { l.Expired = true })); !errors.Is(err, upstreamidp.ErrToken) {
		t.Fatalf("expired token: %v", err)
	}
}

// R9: the discovery document stays in use after the hour if the new read fails.
// A parallel start reads the document one time.
func TestReview_R9_DiscoveryStaleFallback(t *testing.T) {
	p := oidcprovider.Start(t)
	var mu sync.Mutex
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	c := adapter.New(adapter.Config{
		Issuer: "https://id.example.com", HTTPTimeout: 500 * time.Millisecond, Transport: p.Transport(), Now: clock,
		Google: adapter.ProviderConfig{ClientID: oidcprovider.GoogleClientID, ClientSecret: oidcprovider.GoogleSecret},
	})
	if _, err := c.AuthCodeURL(bg, "google", params()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	p.SetDelay("discovery", 3*time.Second)
	if _, err := c.AuthCodeURL(bg, "google", params()); err != nil {
		t.Fatalf("the stale copy must work: %v", err)
	}
	// After one day the copy is too old.
	mu.Lock()
	now = now.Add(25 * time.Hour)
	mu.Unlock()
	if _, err := c.AuthCodeURL(bg, "google", params()); !errors.Is(err, upstreamidp.ErrProvider) {
		t.Fatalf("a copy older than a day: %v", err)
	}
	// Parallel calls after the hour make one read.
	p.SetDelay("discovery", 0)
	before := len(p.Hosts())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.AuthCodeURL(bg, "google", params()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := len(p.Hosts()) - before; got != 1 {
		t.Fatalf("calls to the provider = %d, want 1", got)
	}
}
