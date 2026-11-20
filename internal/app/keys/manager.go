// Package keys holds the signing key manager and the in-memory key cache.
package keys

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/privatekeys"
	"github.com/techorionai/constellation-identity/internal/ports/signingkeys"
)

// Manager runs the lifecycle of the signing keys. Only one instance changes
// the keys at a time, because each pass runs under the cluster lock.
type Manager struct {
	repo   signingkeys.Repository
	store  privatekeys.Store
	policy domain.KeyPolicy
	now    func() time.Time
	log    *slog.Logger
	rotate metric.Int64Counter

	wg   sync.WaitGroup
	stop context.CancelFunc
}

// Option changes a Manager.
type Option func(*Manager)

// WithClock sets the clock. A test uses it to move the time.
func WithClock(now func() time.Time) Option { return func(m *Manager) { m.now = now } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(m *Manager) { m.log = l } }

// NewManager makes a key manager.
func NewManager(repo signingkeys.Repository, store privatekeys.Store, policy domain.KeyPolicy, opts ...Option) *Manager {
	m := &Manager{repo: repo, store: store, policy: policy, now: time.Now, log: slog.Default()}
	for _, o := range opts {
		o(m)
	}
	// The error of a counter in the global meter is not possible. A no-op
	// counter is the fallback.
	m.rotate, _ = otel.Meter("identity").Int64Counter("identity.key_rotation",
		metric.WithDescription("Signing key lifecycle passes by outcome."))
	return m
}

// Run does one pass of the lifecycle under the cluster lock.
func (m *Manager) Run(ctx context.Context) error {
	err := m.repo.WithLock(ctx, m.pass)
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	if m.rotate != nil {
		m.rotate.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	}
	return err
}

// Start runs Run every interval until Close. The first pass is the job of the
// caller.
func (m *Manager) Start(ctx context.Context, interval time.Duration) {
	ctx, m.stop = context.WithCancel(ctx)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := m.Run(ctx); err != nil && ctx.Err() == nil {
					m.log.ErrorContext(ctx, "signing key manager pass failed", "error", err)
				}
			}
		}
	}()
}

// Close stops the loop and waits for it.
func (m *Manager) Close() {
	if m.stop != nil {
		m.stop()
	}
	m.wg.Wait()
}

// ForceRotate deletes all signing keys and their secrets, then makes one new
// active key. All tokens that the old keys signed become invalid.
func (m *Manager) ForceRotate(ctx context.Context) error {
	return m.repo.WithLock(ctx, func(ctx context.Context) error {
		keys, err := m.repo.List(ctx)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if err := m.deleteKey(ctx, k); err != nil {
				return err
			}
		}
		if err := m.deleteOrphans(ctx, nil); err != nil {
			return err
		}
		_, err = m.createKey(ctx, domain.KeyActive, m.now())
		return err
	})
}

func (m *Manager) pass(ctx context.Context) error {
	keys, err := m.repo.List(ctx)
	if err != nil {
		return err
	}
	now := m.now()

	// 1. No active or pending key: make an active key at once.
	if !slices.ContainsFunc(keys, func(k domain.SigningKey) bool {
		return k.State == domain.KeyActive || k.State == domain.KeyPending
	}) {
		k, err := m.createKey(ctx, domain.KeyActive, now)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}

	// 2. The active key is old and no key is pending: make a pending key.
	active := find(keys, domain.KeyActive)
	if active != nil && !slices.ContainsFunc(keys, func(k domain.SigningKey) bool { return k.State == domain.KeyPending }) &&
		now.Sub(active.ActivatesAt) >= m.policy.RotationPeriod {
		k, err := m.createKey(ctx, domain.KeyPending, now.Add(m.policy.PublishDelay))
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}

	// 3. A pending key is due: activate it and retire the old active key.
	for i := range keys {
		if keys[i].State != domain.KeyPending || keys[i].ActivatesAt.After(now) {
			continue
		}
		for j := range keys {
			if keys[j].State == domain.KeyActive {
				if err := m.setState(ctx, &keys[j], domain.KeyRetired, &now); err != nil {
					return err
				}
			}
		}
		if err := m.setState(ctx, &keys[i], domain.KeyActive, nil); err != nil {
			return err
		}
	}

	// 4. Delete a retired key when its time in the JWKS is over.
	live := keys[:0:0]
	for _, k := range keys {
		if k.State == domain.KeyRetired && k.RetiredAt != nil && !k.RetiredAt.Add(m.policy.RetireAfter).After(now) {
			if err := m.deleteKey(ctx, k); err != nil {
				return err
			}
			continue
		}
		live = append(live, k)
	}

	// 5. Delete each secret that has no row.
	return m.deleteOrphans(ctx, live)
}

func find(keys []domain.SigningKey, state domain.KeyState) *domain.SigningKey {
	for i := range keys {
		if keys[i].State == state {
			return &keys[i]
		}
	}
	return nil
}

// createKey writes the secret first, then the row. A failure after the put
// leaves a secret with no row. The next pass deletes it.
func (m *Manager) createKey(ctx context.Context, state domain.KeyState, activatesAt time.Time) (domain.SigningKey, error) {
	now := m.now()
	key, priv, err := domain.NewSigningKey(now, state, activatesAt)
	if err != nil {
		return domain.SigningKey{}, err
	}
	pem, err := domain.EncodePrivateKey(priv)
	if err != nil {
		return domain.SigningKey{}, err
	}
	if err := m.store.Put(ctx, key.PrivateKeyName, pem); err != nil {
		return domain.SigningKey{}, fmt.Errorf("store private key: %w", err)
	}
	if err := m.repo.Insert(ctx, key); err != nil {
		return domain.SigningKey{}, err
	}
	m.logChange(ctx, key.KID, "none", state)
	return key, nil
}

func (m *Manager) setState(ctx context.Context, k *domain.SigningKey, state domain.KeyState, retiredAt *time.Time) error {
	if err := m.repo.UpdateState(ctx, k.KID, state, retiredAt); err != nil {
		return err
	}
	old := k.State
	k.State = state
	k.RetiredAt = retiredAt
	m.logChange(ctx, k.KID, string(old), state)
	return nil
}

// deleteKey deletes the row first, then the secret. A failure after the row
// delete leaves a secret with no row. The next pass deletes it.
func (m *Manager) deleteKey(ctx context.Context, k domain.SigningKey) error {
	if err := m.repo.Delete(ctx, k.KID); err != nil {
		return err
	}
	m.logChange(ctx, k.KID, string(k.State), "deleted")
	if err := m.store.Delete(ctx, k.PrivateKeyName); err != nil {
		return fmt.Errorf("delete private key: %w", err)
	}
	return nil
}

func (m *Manager) deleteOrphans(ctx context.Context, keys []domain.SigningKey) error {
	names, err := m.store.ListNames(ctx, domain.SigningKeyPrefix)
	if err != nil {
		return fmt.Errorf("list private keys: %w", err)
	}
	var errs []error
	for _, name := range names {
		if slices.ContainsFunc(keys, func(k domain.SigningKey) bool { return k.PrivateKeyName == name }) {
			continue
		}
		if err := m.store.Delete(ctx, name); err != nil {
			errs = append(errs, fmt.Errorf("delete orphan private key: %w", err))
			continue
		}
		m.log.InfoContext(ctx, "signing key secret with no row deleted", "name", name)
	}
	return errors.Join(errs...)
}

func (m *Manager) logChange(ctx context.Context, kid, from string, to domain.KeyState) {
	m.log.InfoContext(ctx, "signing key state changed", "kid", kid, "old_state", from, "new_state", string(to))
}
