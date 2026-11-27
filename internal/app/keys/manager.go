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

	"github.com/techorionai/constellation-platform-go/audit"
	"github.com/techorionai/constellation-platform-go/transaction"
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
	tx     transaction.Transactor
	audit  audit.Writer

	mu   sync.Mutex // Protects stop.
	wg   sync.WaitGroup
	stop context.CancelFunc
}

// Option changes a Manager.
type Option func(*Manager)

// WithClock sets the clock. A test uses it to move the time.
func WithClock(now func() time.Time) Option { return func(m *Manager) { m.now = now } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(m *Manager) { m.log = l } }

// WithAudit sets the transactor and the audit writer. Each change of a key
// writes its audit entry in the transaction of the change. The manager does not
// change a key without them.
func WithAudit(tx transaction.Transactor, w audit.Writer) Option {
	return func(m *Manager) { m.tx, m.audit = tx, w }
}

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
// caller. If the loop already runs, Start does nothing.
func (m *Manager) Start(ctx context.Context, interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stop != nil {
		return
	}
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
	m.mu.Lock()
	stop := m.stop
	m.stop = nil
	m.mu.Unlock()
	if stop != nil {
		stop()
	}
	m.wg.Wait()
}

// ForceRotate deletes all signing keys and their secrets, then makes one new
// active key. All tokens that the old keys signed become invalid. The new
// secret is stored first. One transaction then deletes the rows, inserts the
// new row, and writes the entries. After the commit, the old secrets are
// deleted. A failure before the commit leaves the old keys. The next pass
// deletes the new secret that has no row. A failure after the commit leaves
// old secrets that the next pass deletes.
func (m *Manager) ForceRotate(ctx context.Context) error {
	return m.repo.WithLock(ctx, func(ctx context.Context) error {
		if err := m.checkAudit(); err != nil {
			return err
		}
		old, err := m.repo.List(ctx)
		if err != nil {
			return err
		}
		fresh, err := m.newKey(ctx, domain.KeyActive, m.now())
		if err != nil {
			return err
		}
		err = m.tx.WithinTx(ctx, func(ctx context.Context) error {
			// The entries come before the row changes. A writer error stops
			// the rotation before any row changes.
			entries := make([]audit.Entry, 0, len(old)+2)
			for _, k := range old {
				entries = append(entries, m.entry(ActionDelete, k.KID, map[string]any{"forced": true, "origin": OriginCLI}))
			}
			entries = append(entries,
				m.entry(ActionCreate, fresh.KID, createDetails(fresh, OriginCLI)),
				m.entry(ActionForceRotate, fresh.KID, map[string]any{"deletedKeys": len(old), "newKid": fresh.KID, "origin": OriginCLI}))
			if err := m.write(ctx, entries...); err != nil {
				return err
			}
			for _, k := range old {
				if err := m.repo.Delete(ctx, k.KID); err != nil {
					return err
				}
			}
			return m.repo.Insert(ctx, fresh)
		}, transaction.Name("force_rotate_signing_keys"))
		if err != nil {
			return err
		}
		for _, k := range old {
			m.logChange(ctx, k.KID, string(k.State), "deleted")
		}
		m.logChange(ctx, fresh.KID, "none", domain.KeyActive)
		return m.deleteSecrets(ctx, []domain.SigningKey{fresh})
	})
}

func (m *Manager) pass(ctx context.Context) error {
	all, err := m.repo.List(ctx)
	if err != nil {
		return err
	}
	keys := m.validRows(ctx, all)
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
	// Both changes are one transaction. The secret of the old key goes in
	// step 5.
	for i := range keys {
		if keys[i].State != domain.KeyPending || keys[i].ActivatesAt.After(now) {
			continue
		}
		if err := m.activate(ctx, keys, i, now); err != nil {
			return err
		}
	}

	// 4. Delete the row of a retired key when its time in the JWKS is over.
	live := keys[:0:0]
	for _, k := range keys {
		if k.State == domain.KeyRetired && !retiredSince(k).Add(m.policy.RetireAfter).After(now) {
			if err := m.deleteRow(ctx, k); err != nil {
				return err
			}
			m.logChange(ctx, k.KID, string(k.State), "deleted")
			continue
		}
		live = append(live, k)
	}

	// 5. Delete each secret that has no row, or whose row is retired.
	return m.deleteSecrets(ctx, live)
}

// validRows returns the rows that pass SigningKey.Validate. The manager
// ignores each other row. Such a row is never counted as pending or active and
// never activated. It cannot make the manager delete the secret of a valid
// key. Each ignored row gets an error log record.
func (m *Manager) validRows(ctx context.Context, all []domain.SigningKey) []domain.SigningKey {
	rows := make([]domain.SigningKey, 0, len(all))
	for _, row := range all {
		if err := row.Validate(); err != nil {
			m.log.ErrorContext(ctx, "signing key row is not valid and is ignored", "kid", row.KID, "error", err)
			continue
		}
		rows = append(rows, row)
	}
	return rows
}

// retiredSince returns the time that the key became retired. A retired row
// with no retired_at uses created_at, so that the row does not stay for ever.
func retiredSince(k domain.SigningKey) time.Time {
	if k.RetiredAt != nil {
		return *k.RetiredAt
	}
	return k.CreatedAt
}

// activate makes keys[i] active and retires each active key in one
// transaction. On an error, the keys keep their states.
func (m *Manager) activate(ctx context.Context, keys []domain.SigningKey, i int, now time.Time) error {
	if err := m.checkAudit(); err != nil {
		return err
	}
	var retire []string
	for _, k := range keys {
		if k.State == domain.KeyActive {
			retire = append(retire, k.KID)
		}
	}
	err := m.tx.WithinTx(ctx, func(ctx context.Context) error {
		entries := make([]audit.Entry, 0, len(retire)+1)
		for _, kid := range retire {
			entries = append(entries, m.entry(ActionRetire, kid, nil))
		}
		previous := ""
		if len(retire) > 0 {
			previous = retire[0]
		}
		entries = append(entries, m.entry(ActionActivate, keys[i].KID, map[string]any{"previousKid": previous}))
		// The entries come before the row changes. A writer error stops the
		// activation, and the old key stays active.
		if err := m.write(ctx, entries...); err != nil {
			return err
		}
		return m.repo.Activate(ctx, keys[i].KID, retire, now)
	}, transaction.Name("activate_signing_key_audited"))
	if err != nil {
		return err
	}
	for j := range keys {
		if keys[j].State == domain.KeyActive {
			keys[j].State = domain.KeyRetired
			keys[j].RetiredAt = &now
			m.logChange(ctx, keys[j].KID, string(domain.KeyActive), domain.KeyRetired)
		}
	}
	keys[i].State = domain.KeyActive
	keys[i].RetiredAt = nil
	m.logChange(ctx, keys[i].KID, string(domain.KeyPending), domain.KeyActive)
	return nil
}

func find(keys []domain.SigningKey, state domain.KeyState) *domain.SigningKey {
	for i := range keys {
		if keys[i].State == state {
			return &keys[i]
		}
	}
	return nil
}

// newKey makes a key and stores its secret. A failure after the put leaves a
// secret with no row. The next pass deletes it.
func (m *Manager) newKey(ctx context.Context, state domain.KeyState, activatesAt time.Time) (domain.SigningKey, error) {
	key, priv, err := domain.NewSigningKey(m.now(), state, activatesAt)
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
	return key, nil
}

// createKey writes the secret first. Then one transaction inserts the row and
// writes the audit entry.
func (m *Manager) createKey(ctx context.Context, state domain.KeyState, activatesAt time.Time) (domain.SigningKey, error) {
	if err := m.checkAudit(); err != nil {
		return domain.SigningKey{}, err
	}
	key, err := m.newKey(ctx, state, activatesAt)
	if err != nil {
		return domain.SigningKey{}, err
	}
	err = m.tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := m.write(ctx, m.entry(ActionCreate, key.KID, createDetails(key, ""))); err != nil {
			return err
		}
		return m.repo.Insert(ctx, key)
	}, transaction.Name("create_signing_key"))
	if err != nil {
		return domain.SigningKey{}, err
	}
	m.logChange(ctx, key.KID, "none", state)
	return key, nil
}

// deleteRow deletes the row of a retired key and writes its audit entry in one
// transaction. The secret goes later in deleteSecrets.
func (m *Manager) deleteRow(ctx context.Context, k domain.SigningKey) error {
	if err := m.checkAudit(); err != nil {
		return err
	}
	return m.tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := m.write(ctx, m.entry(ActionDelete, k.KID, map[string]any{"forced": false})); err != nil {
			return err
		}
		return m.repo.Delete(ctx, k.KID)
	}, transaction.Name("delete_signing_key"))
}

// deleteSecrets deletes each secret under the prefix that has no row, or whose
// row is retired. A retired key does not sign, so it needs no private key.
func (m *Manager) deleteSecrets(ctx context.Context, keys []domain.SigningKey) error {
	names, err := m.store.ListNames(ctx, domain.SigningKeyPrefix)
	if err != nil {
		return fmt.Errorf("list private keys: %w", err)
	}
	var errs []error
	for _, name := range names {
		if slices.ContainsFunc(keys, func(k domain.SigningKey) bool {
			return k.PrivateKeyName == name && k.State != domain.KeyRetired
		}) {
			continue
		}
		if err := m.store.Delete(ctx, name); err != nil {
			errs = append(errs, fmt.Errorf("delete private key: %w", err))
			continue
		}
		m.log.InfoContext(ctx, "signing key secret deleted: no row or retired row", "name", name)
	}
	return errors.Join(errs...)
}

func (m *Manager) logChange(ctx context.Context, kid, from string, to domain.KeyState) {
	m.log.InfoContext(ctx, "signing key state changed", "kid", kid, "old_state", from, "new_state", string(to))
}
