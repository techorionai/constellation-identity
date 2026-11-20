package keys_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
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
	recs := r.records(t)
	if len(recs) != 2 {
		t.Fatalf("log records = %d, want 2", len(recs))
	}
	for _, rec := range recs {
		if rec["level"] != "INFO" || rec["kid"] == nil || rec["old_state"] == nil || rec["new_state"] == nil {
			t.Fatalf("record = %v", rec)
		}
	}
	if strings.Contains(r.logs.String(), "PRIVATE KEY") {
		t.Fatal("log has a private key")
	}
}

// U4: a retired key is deleted after RetireAfter. The row goes first.
func TestU4_RetiredKeyIsDeleted(t *testing.T) {
	r := newRig()
	first := r.run(t)[0]
	r.clock.Add(policy.RotationPeriod + time.Minute)
	r.run(t)
	r.clock.Add(policy.PublishDelay)
	r.run(t)

	var order []string
	r.repo.DeleteHook = func(string) error { order = append(order, "row"); return nil }
	r.store.DeleteHook = func(string) error { order = append(order, "secret"); return nil }

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
	if strings.Join(order, ",") != "row,secret" {
		t.Fatalf("delete order = %v", order)
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

// U4b: the secret delete fails after the row delete. The next run deletes it.
func TestU4b_FailureAfterRowDeleteLeavesNoRow(t *testing.T) {
	r := newRig()
	first := r.run(t)[0]
	r.clock.Add(policy.RotationPeriod + time.Minute)
	r.run(t)
	r.clock.Add(policy.PublishDelay)
	r.run(t)
	r.clock.Add(policy.RetireAfter)

	r.store.DeleteHook = func(string) error { return errors.New("delete failed") }
	if err := r.mgr.Run(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	ks, _ := r.repo.List(context.Background())
	if len(ks) != 1 {
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
		t.Fatal("the next run must delete the secret with no row")
	}
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
