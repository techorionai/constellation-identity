package keys_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/keys"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time      { return c.now }
func (c *testClock) Add(d time.Duration) { c.now = c.now.Add(d) }
func newClock() *testClock               { return &testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }
func states(ks []domain.SigningKey) []string {
	out := make([]string, 0, len(ks))
	for _, k := range ks {
		out = append(out, string(k.State))
	}
	return out
}

var policy = domain.KeyPolicy{RotationPeriod: 90 * 24 * time.Hour, PublishDelay: time.Hour, RetireAfter: 24 * time.Hour}

type rig struct {
	repo  *mock.SigningKeys
	store *mock.PrivateKeys
	clock *testClock
	logs  *bytes.Buffer
	mgr   *keys.Manager
}

func newRig() *rig { return newRigWith(policy) }

func newRigWith(p domain.KeyPolicy) *rig {
	r := &rig{repo: &mock.SigningKeys{}, store: &mock.PrivateKeys{}, clock: newClock(), logs: &bytes.Buffer{}}
	log := slog.New(slog.NewJSONHandler(r.logs, nil))
	r.mgr = keys.NewManager(r.repo, r.store, p, keys.WithClock(r.clock.Now), keys.WithLogger(log))
	return r
}

func (r *rig) run(t *testing.T) []domain.SigningKey {
	t.Helper()
	if err := r.mgr.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	ks, _ := r.repo.List(context.Background())
	return ks
}

func (r *rig) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(r.logs.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// U1: no keys gives one active key.
func TestU1_FirstStartMakesActiveKey(t *testing.T) {
	r := newRig()
	ks := r.run(t)
	if len(ks) != 1 || ks[0].State != domain.KeyActive {
		t.Fatalf("keys = %v, want one active key", states(ks))
	}
	if len(r.store.Names()) != 1 || r.store.Names()[0] != domain.PrivateKeyName(ks[0].KID) {
		t.Fatalf("secret names = %v", r.store.Names())
	}
	// A second run changes nothing.
	if ks2 := r.run(t); len(ks2) != 1 {
		t.Fatalf("second run made %d keys", len(ks2))
	}
}

// U2: an old active key gives one pending key, and not a second one.
func TestU2_RotationMakesOnePendingKey(t *testing.T) {
	r := newRig()
	r.run(t)
	r.clock.Add(policy.RotationPeriod + time.Minute)
	ks := r.run(t)
	if got := states(ks); len(got) != 2 || got[0] != "active" || got[1] != "pending" {
		t.Fatalf("states = %v", got)
	}
	want := r.clock.now.Add(policy.PublishDelay)
	if !ks[1].ActivatesAt.Equal(want) {
		t.Fatalf("activates_at = %v, want %v", ks[1].ActivatesAt, want)
	}
	r.clock.Add(time.Minute)
	if got := r.run(t); len(got) != 2 {
		t.Fatalf("second run: %v", states(got))
	}
}

// U3: a due pending key becomes active and the old key is retired.
func TestU3_PendingKeyBecomesActive(t *testing.T) {
	r := newRig()
	first := r.run(t)[0]
	r.clock.Add(policy.RotationPeriod + time.Minute)
	r.run(t)
	r.logs.Reset()
	r.clock.Add(policy.PublishDelay)
	ks := r.run(t)
	if len(ks) != 2 {
		t.Fatalf("keys = %v", states(ks))
	}
	for _, k := range ks {
		switch k.KID {
		case first.KID:
			if k.State != domain.KeyRetired || k.RetiredAt == nil || !k.RetiredAt.Equal(r.clock.now) {
				t.Fatalf("old key = %+v", k)
			}
		default:
			if k.State != domain.KeyActive {
				t.Fatalf("new key state = %s", k.State)
			}
		}
	}
	// R23: the private key of the retired key is deleted in the same pass.
	for _, name := range r.store.Names() {
		if name == domain.PrivateKeyName(first.KID) {
			t.Fatal("the secret of the retired key stays")
		}
	}
	if len(r.store.Names()) != 1 {
		t.Fatalf("secrets = %v, want only the secret of the active key", r.store.Names())
	}
	recs := r.records(t)
	if len(recs) < 2 {
		t.Fatalf("log records = %d, want 2 state changes", len(recs))
	}
	var changes []map[string]any
	for _, rec := range recs {
		if rec["msg"] == "signing key state changed" {
			changes = append(changes, rec)
		}
	}
	if len(changes) != 2 {
		t.Fatalf("state change records = %d, want 2", len(changes))
	}
	for _, rec := range changes {
		if rec["level"] != "INFO" || rec["kid"] == nil || rec["old_state"] == nil || rec["new_state"] == nil {
			t.Fatalf("record = %v", rec)
		}
	}
	if strings.Contains(r.logs.String(), "PRIVATE KEY") {
		t.Fatal("log has a private key")
	}
}

// U4: a retired key row is deleted after RetireAfter. The secret was deleted
// when the key became retired.
func TestU4_RetiredKeyIsDeleted(t *testing.T) {
	r := newRig()
	first := r.run(t)[0]
	r.clock.Add(policy.RotationPeriod + time.Minute)
	r.run(t)
	r.clock.Add(policy.PublishDelay)
	r.run(t)
	if len(r.store.Names()) != 1 {
		t.Fatalf("secrets after the retire = %v, want 1", r.store.Names())
	}

	var deletes []string
	r.store.DeleteHook = func(n string) error { deletes = append(deletes, n); return nil }

	r.clock.Add(policy.RetireAfter - time.Second)
	if ks, _ := r.repo.List(context.Background()); len(ks) != 2 {
		t.Fatal("setup")
	}
	r.run(t)
	if ks, _ := r.repo.List(context.Background()); len(ks) != 2 {
		t.Fatalf("key deleted too early: %v", states(ks))
	}
	r.clock.Add(time.Second)
	ks := r.run(t)
	if len(ks) != 1 || ks[0].KID == first.KID {
		t.Fatalf("keys after delete = %v", states(ks))
	}
	if len(deletes) != 0 {
		t.Fatalf("secret deletes at the row delete = %v, want none", deletes)
	}
	if len(r.store.Names()) != 1 {
		t.Fatalf("secrets = %v", r.store.Names())
	}
}

// U4a: the row insert fails after the put. The next run deletes the secret.
func TestU4a_FailureAfterPutLeavesNoRow(t *testing.T) {
	r := newRig()
	r.repo.InsertHook = func(domain.SigningKey) error { return errors.New("insert failed") }
	if err := r.mgr.Run(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	if ks, _ := r.repo.List(context.Background()); len(ks) != 0 {
		t.Fatalf("rows = %d", len(ks))
	}
	if len(r.store.Names()) != 1 {
		t.Fatalf("secrets = %v, want one secret with no row", r.store.Names())
	}
	r.repo.InsertHook = nil
	ks := r.run(t)
	if len(ks) != 1 {
		t.Fatalf("rows = %d", len(ks))
	}
	names := r.store.Names()
	if len(names) != 1 || names[0] != ks[0].PrivateKeyName {
		t.Fatalf("secrets after the second run = %v", names)
	}
}

// U4b: the secret delete fails when the key becomes retired. The row is
// retired and the secret stays. The next run deletes the secret.
func TestU4b_FailureAtRetireLeavesSecretOfRetiredRow(t *testing.T) {
	r := newRig()
	first := r.run(t)[0]
	r.clock.Add(policy.RotationPeriod + time.Minute)
	r.run(t)
	r.clock.Add(policy.PublishDelay)

	r.store.DeleteHook = func(string) error { return errors.New("delete failed") }
	if err := r.mgr.Run(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	ks, _ := r.repo.List(context.Background())
	if len(ks) != 2 || ks[0].KID != first.KID || ks[0].State != domain.KeyRetired {
		t.Fatalf("rows = %v", states(ks))
	}
	has := func(name string) bool {
		for _, n := range r.store.Names() {
			if n == name {
				return true
			}
		}
		return false
	}
	if !has(domain.PrivateKeyName(first.KID)) {
		t.Fatal("the secret must stay after the failed delete")
	}
	r.store.DeleteHook = nil
	r.run(t)
	if has(domain.PrivateKeyName(first.KID)) {
		t.Fatal("the next run must delete the secret of the retired row")
	}
	if ks, _ := r.repo.List(context.Background()); len(ks) != 2 {
		t.Fatalf("the retired row must stay until RetireAfter: %v", states(ks))
	}
}

// R10: the activation is one transaction. A failure of the second write
// leaves the old states, so the service never has no active key.
func TestR10_ActivationIsAtomic(t *testing.T) {
	r := newRig()
	first := r.run(t)[0]
	r.clock.Add(policy.RotationPeriod + time.Minute)
	r.run(t)
	r.clock.Add(policy.PublishDelay)

	r.repo.UpdateStateHook = func(_ string, state domain.KeyState) error {
		if state == domain.KeyActive {
			return errors.New("second write failed")
		}
		return nil
	}
	if err := r.mgr.Run(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	ks, _ := r.repo.List(context.Background())
	var active []string
	for _, k := range ks {
		if k.State == domain.KeyActive {
			active = append(active, k.KID)
		}
	}
	if len(active) != 1 || active[0] != first.KID {
		t.Fatalf("states after the failure = %v, want the old key active", states(ks))
	}
	r.repo.UpdateStateHook = nil
	ks = r.run(t)
	if got := strings.Join(states(ks), ","); got != "retired,active" {
		t.Fatalf("states after the repair = %s", got)
	}
}

// R13: a retired row with no retired_at is deleted after RetireAfter.
func TestR13_RetiredRowWithoutTimeIsDeleted(t *testing.T) {
	r := newRig()
	first := r.run(t)[0]
	r.clock.Add(policy.RotationPeriod + time.Minute)
	r.run(t)
	r.clock.Add(policy.PublishDelay)
	r.run(t)
	if err := r.repo.UpdateState(context.Background(), first.KID, domain.KeyRetired, nil); err != nil {
		t.Fatal(err)
	}
	r.clock.Add(policy.RetireAfter)
	ks := r.run(t)
	if len(ks) != 1 || ks[0].KID == first.KID {
		t.Fatalf("keys = %v", states(ks))
	}
}

// R11: a second Start does not start a second loop. Close stops the loop.
func TestR11_StartTwiceAndClose(t *testing.T) {
	r := newRig()
	ctx := context.Background()
	r.mgr.Start(ctx, time.Hour)
	r.mgr.Start(ctx, time.Hour)
	cache := keys.NewCache(r.repo, r.store, nil)
	cache.Start(ctx, time.Hour)
	cache.Start(ctx, time.Hour)
	done := make(chan struct{})
	go func() {
		r.mgr.Close()
		cache.Close()
		r.mgr.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close does not stop the loops")
	}
}

// R12: Reload calls at the same time are safe and end with the newest state.
func TestR12_ConcurrentReload(t *testing.T) {
	r := newRig()
	r.run(t)
	cache := keys.NewCache(r.repo, r.store, nil)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				if err := cache.Reload(context.Background()); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if !cache.HasActive() {
		t.Fatal("the cache has no active key")
	}
}

// R22: the cache does not serve a row whose kid is not the thumbprint of its
// key, or whose members are wrong.
func TestR22_CacheRejectsRowsNotBoundToKid(t *testing.T) {
	good, _, err := domain.NewSigningKey(time.Now(), domain.KeyActive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := domain.NewSigningKey(time.Now(), domain.KeyPending, time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	mut := func(f func(k *domain.SigningKey)) domain.SigningKey {
		k := other
		f(&k)
		return k
	}
	bad := map[string]domain.SigningKey{
		"kid is not the thumbprint": mut(func(k *domain.SigningKey) {
			k.KID = "attacker"
			k.PublicJWK.Kid = "attacker"
			k.PrivateKeyName = domain.PrivateKeyName("attacker")
		}),
		"jwk kid differs":        mut(func(k *domain.SigningKey) { k.PublicJWK.Kid = "x" }),
		"wrong kty":              mut(func(k *domain.SigningKey) { k.PublicJWK.Kty = "RSA" }),
		"wrong crv":              mut(func(k *domain.SigningKey) { k.PublicJWK.Crv = "P-384" }),
		"wrong alg":              mut(func(k *domain.SigningKey) { k.PublicJWK.Alg = "HS256" }),
		"wrong use":              mut(func(k *domain.SigningKey) { k.PublicJWK.Use = "enc" }),
		"wrong private key name": mut(func(k *domain.SigningKey) { k.PrivateKeyName = domain.PrivateKeyName("other") }),
	}
	for name, row := range bad {
		t.Run(name, func(t *testing.T) {
			r := newRig()
			// A valid active key with its secret, from the manager.
			active := r.run(t)[0]
			if err := r.repo.Insert(context.Background(), row); err != nil {
				t.Fatal(err)
			}
			cache := keys.NewCache(r.repo, r.store, slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
			if err := cache.Reload(context.Background()); err != nil {
				t.Fatal(err)
			}
			jwks := cache.JWKS()
			if len(jwks) != 1 || jwks[0].Kid != active.KID {
				t.Fatalf("jwks = %+v, want only the valid key", jwks)
			}
		})
	}
	t.Run("valid row passes", func(t *testing.T) {
		if err := good.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := other.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

// U5: the cache JWKS has pending, active, and retired keys and no private field.
func TestU5_JWKSHasAllStatesAndNoPrivateFields(t *testing.T) {
	long := policy
	long.RetireAfter = 365 * 24 * time.Hour
	r := newRigWith(long)
	r.run(t)
	r.clock.Add(policy.RotationPeriod + time.Minute)
	r.run(t) // active + pending
	r.clock.Add(policy.PublishDelay)
	r.run(t) // retired + active
	r.clock.Add(policy.RotationPeriod + time.Minute)
	r.run(t) // + pending

	cache := keys.NewCache(r.repo, r.store, slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
	if err := cache.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	counts := cache.Counts()
	if counts[domain.KeyPending] != 1 || counts[domain.KeyActive] != 1 || counts[domain.KeyRetired] != 1 {
		t.Fatalf("counts = %v", counts)
	}
	data, err := json.Marshal(cache.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	var generic []map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	if len(generic) != 3 {
		t.Fatalf("jwks has %d keys", len(generic))
	}
	for _, k := range generic {
		for name := range k {
			if domain.IsPrivateJWKField(name) {
				t.Fatalf("jwks has the private field %s", name)
			}
		}
	}
	if _, err := cache.ActiveKey(); err != nil {
		t.Fatal(err)
	}
}

// ForceRotate replaces all keys.
func TestForceRotate(t *testing.T) {
	r := newRig()
	old := r.run(t)[0]
	if err := r.mgr.ForceRotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ks, _ := r.repo.List(context.Background())
	if len(ks) != 1 || ks[0].KID == old.KID || ks[0].State != domain.KeyActive {
		t.Fatalf("keys = %+v", ks)
	}
	if len(r.store.Names()) != 1 {
		t.Fatalf("secrets = %v", r.store.Names())
	}
}

func TestCacheKeepsOldContentOnError(t *testing.T) {
	r := newRig()
	r.run(t)
	cache := keys.NewCache(r.repo, r.store, nil)
	if err := cache.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A different store has no private key for the active row.
	broken := keys.NewCache(r.repo, &mock.PrivateKeys{}, nil)
	if err := broken.Reload(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	if broken.HasActive() {
		t.Fatal("broken cache must have no active key")
	}
	if !cache.HasActive() {
		t.Fatal("good cache must have an active key")
	}
}

// attackerRow returns a pending row whose kid is not the thumbprint of its key.
func attackerRow(t *testing.T, activatesAt time.Time) domain.SigningKey {
	t.Helper()
	row, _, err := domain.NewSigningKey(time.Now(), domain.KeyPending, activatesAt)
	if err != nil {
		t.Fatal(err)
	}
	row.KID = "attacker"
	row.PublicJWK.Kid = "attacker"
	row.PrivateKeyName = domain.PrivateKeyName("attacker")
	return row
}

// hasErrorRecord reports whether the logs have an error record for the kid.
func (r *rig) hasErrorRecord(t *testing.T, kid string) bool {
	t.Helper()
	for _, rec := range r.records(t) {
		if rec["level"] == "ERROR" && rec["kid"] == kid {
			return true
		}
	}
	return false
}

// U20 (R22): an invalid pending row with a far activation time does not stop
// the rotation.
func TestU20_InvalidFuturePendingRowDoesNotStopRotation(t *testing.T) {
	r := newRig()
	r.run(t)
	if err := r.repo.Insert(context.Background(), attackerRow(t, r.clock.now.AddDate(1, 0, 0))); err != nil {
		t.Fatal(err)
	}
	r.clock.Add(policy.RotationPeriod + time.Minute)
	ks := r.run(t)
	valid := 0
	for _, k := range ks {
		if k.KID != "attacker" && k.State == domain.KeyPending {
			valid++
		}
	}
	if valid != 1 {
		t.Fatalf("valid pending keys = %d, want 1 (states %v)", valid, states(ks))
	}
	if !r.hasErrorRecord(t, "attacker") {
		t.Fatal("no error log record with the kid of the invalid row")
	}
}

// U21 (R22): an invalid pending row that is due is not activated. The real
// active key and its secret stay.
func TestU21_InvalidDuePendingRowIsNotActivated(t *testing.T) {
	r := newRig()
	active := r.run(t)[0]
	if err := r.repo.Insert(context.Background(), attackerRow(t, r.clock.now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	r.clock.Add(time.Minute)
	ks := r.run(t)
	for _, k := range ks {
		switch k.KID {
		case active.KID:
			if k.State != domain.KeyActive {
				t.Fatalf("real key state = %s, want active", k.State)
			}
		case "attacker":
			if k.State != domain.KeyPending {
				t.Fatalf("attacker state = %s, want pending", k.State)
			}
		}
	}
	if _, err := r.store.Get(context.Background(), active.PrivateKeyName); err != nil {
		t.Fatalf("the secret of the real key is gone: %v", err)
	}
	if !r.hasErrorRecord(t, "attacker") {
		t.Fatal("no error log record with the kid of the invalid row")
	}
}
