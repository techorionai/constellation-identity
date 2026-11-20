package keys

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/privatekeys"
	"github.com/techorionai/constellation-identity/internal/ports/signingkeys"
	"github.com/techorionai/constellation-identity/internal/ports/tokensigner"
)

// ErrNoActiveKey means the cache has no active signing key.
var ErrNoActiveKey = errors.New("no active signing key")

// Cache holds the public key set and the decrypted active private key in
// memory. It gives the JWKS and the active key to the use cases.
type Cache struct {
	repo  signingkeys.Repository
	store privatekeys.Store
	log   *slog.Logger

	reloadMu sync.Mutex // Serializes Reload.

	mu     sync.RWMutex
	keys   []domain.SigningKey
	active *tokensigner.Key

	stopMu sync.Mutex // Protects stop.
	wg     sync.WaitGroup
	stop   context.CancelFunc
}

// NewCache makes an empty cache. Call Reload before use.
func NewCache(repo signingkeys.Repository, store privatekeys.Store, log *slog.Logger) *Cache {
	if log == nil {
		log = slog.Default()
	}
	return &Cache{repo: repo, store: store, log: log}
}

// Reload reads the keys. It decrypts the private key of the active key when
// the active key is new. On an error, the cache keeps its old content. A row
// that fails SigningKey.Validate is not served and is logged. Calls of Reload
// run one at a time.
func (c *Cache) Reload(ctx context.Context) error {
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	all, err := c.repo.List(ctx)
	if err != nil {
		return err
	}
	rows := make([]domain.SigningKey, 0, len(all))
	for _, row := range all {
		if err := row.Validate(); err != nil {
			c.log.ErrorContext(ctx, "signing key row is not valid and is not served", "kid", row.KID, "error", err)
			continue
		}
		rows = append(rows, row)
	}
	var activeRow *domain.SigningKey
	for i := range rows {
		if rows[i].State == domain.KeyActive {
			activeRow = &rows[i]
		}
	}

	c.mu.RLock()
	current := c.active
	c.mu.RUnlock()

	next := current
	switch {
	case activeRow == nil:
		next = nil
	case current == nil || current.KID != activeRow.KID:
		pem, err := c.store.Get(ctx, activeRow.PrivateKeyName)
		if err != nil {
			return fmt.Errorf("load active signing key %s: %w", activeRow.KID, err)
		}
		priv, err := domain.DecodePrivateKey(pem)
		if err != nil {
			return fmt.Errorf("decode active signing key %s: %w", activeRow.KID, err)
		}
		if domain.Thumbprint(&priv.PublicKey) != activeRow.KID {
			return fmt.Errorf("active signing key %s: the private key does not match the kid", activeRow.KID)
		}
		next = &tokensigner.Key{KID: activeRow.KID, Private: priv}
	}

	c.mu.Lock()
	c.keys = rows
	c.active = next
	c.mu.Unlock()
	return nil
}

// Start reloads the cache every interval until Close. If the loop already
// runs, Start does nothing.
func (c *Cache) Start(ctx context.Context, interval time.Duration) {
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	if c.stop != nil {
		return
	}
	ctx, c.stop = context.WithCancel(ctx)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := c.Reload(ctx); err != nil && ctx.Err() == nil {
					c.log.ErrorContext(ctx, "signing key cache reload failed", "error", err)
				}
			}
		}
	}()
}

// Close stops the reload loop and waits for it.
func (c *Cache) Close() {
	c.stopMu.Lock()
	stop := c.stop
	c.stop = nil
	c.stopMu.Unlock()
	if stop != nil {
		stop()
	}
	c.wg.Wait()
}

// HasActive reports whether the cache has an active signing key.
func (c *Cache) HasActive() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.active != nil
}

// ActiveKey returns the key that signs.
func (c *Cache) ActiveKey() (tokensigner.Key, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.active == nil {
		return tokensigner.Key{}, ErrNoActiveKey
	}
	return *c.active, nil
}

// JWKS returns the public keys: pending, active, and retired.
func (c *Cache) JWKS() []domain.PublicJWK {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]domain.PublicJWK, 0, len(c.keys))
	for _, k := range c.keys {
		out = append(out, k.PublicJWK)
	}
	return out
}

// Counts returns the number of keys in each state.
func (c *Cache) Counts() map[domain.KeyState]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := map[domain.KeyState]int{domain.KeyPending: 0, domain.KeyActive: 0, domain.KeyRetired: 0}
	for _, k := range c.keys {
		out[k.State]++
	}
	return out
}
