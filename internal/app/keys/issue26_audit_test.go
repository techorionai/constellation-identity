package keys_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/techorionai/constellation-platform-go/audit"
	platformmock "github.com/techorionai/constellation-platform-go/resources/test/mock"

	"github.com/techorionai/constellation-identity/internal/app/keys"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

type keyEvent struct {
	Actor     string `json:"actor"`
	ActorType string `json:"actortype"`
	Data      struct {
		Action  string         `json:"action"`
		Result  string         `json:"result"`
		Details map[string]any `json:"details"`
		Target  *struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"target"`
	} `json:"data"`
}

// realWriterRig is a key manager with the real audit writer and a mock inserter.
func realWriterRig(t *testing.T) (*rig, *platformmock.AuditInserter) {
	t.Helper()
	r := newRig()
	ins := &platformmock.AuditInserter{}
	w, err := audit.New(ins, audit.Config{App: "identity", ClientID: "identity"})
	if err != nil {
		t.Fatal(err)
	}
	r.mgr = keys.NewManager(r.repo, r.store, policy, keys.WithClock(r.clock.Now), keys.WithAudit(mock.Tx{}, w))
	return r, ins
}

func events(t *testing.T, ins *platformmock.AuditInserter) []keyEvent {
	t.Helper()
	var out []keyEvent
	for _, row := range ins.Rows() {
		var e keyEvent
		if err := json.Unmarshal(row.Payload, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func actions(evs []keyEvent) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Data.Action)
	}
	return out
}

// Issue26_U1: create, activate, retire, and delete write one entry each. The
// actor is the service identity and the entries have no origin.
func TestIssue26_U1_KeyActionsWriteEntries(t *testing.T) {
	r, ins := realWriterRig(t)
	first := r.run(t)[0]
	r.clock.Add(policy.RotationPeriod + 1)
	r.run(t) // pending key
	r.clock.Add(policy.PublishDelay)
	r.run(t) // activate and retire
	r.clock.Add(policy.RetireAfter + 1)
	r.run(t) // delete
	evs := events(t, ins)
	want := []string{
		keys.ActionCreate, keys.ActionCreate, keys.ActionRetire, keys.ActionActivate, keys.ActionDelete,
	}
	got := actions(evs)
	if len(got) != len(want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("actions = %v, want %v", got, want)
		}
	}
	for _, e := range evs {
		if e.Actor != "identity" || e.ActorType != "service" || e.Data.Result != "success" {
			t.Fatalf("entry = %+v", e)
		}
		if _, ok := e.Data.Details["origin"]; ok {
			t.Fatalf("an automatic key action has no origin: %+v", e.Data.Details)
		}
		if e.Data.Target == nil || e.Data.Target.Type != "signing_key" || e.Data.Target.ID == "" {
			t.Fatalf("target = %+v", e.Data.Target)
		}
	}
	if evs[0].Data.Target.ID != first.KID || evs[0].Data.Details["state"] != "active" || evs[0].Data.Details["algorithm"] == "" {
		t.Fatalf("create entry = %+v", evs[0].Data)
	}
	if evs[3].Data.Details["previousKid"] != first.KID || evs[2].Data.Target.ID != first.KID {
		t.Fatalf("activate and retire entries = %+v %+v", evs[2].Data, evs[3].Data)
	}
	if evs[4].Data.Target.ID != first.KID || evs[4].Data.Details["forced"] != false {
		t.Fatalf("delete entry = %+v", evs[4].Data)
	}
}

// Issue26_U2: a writer error during the activation stops it. The old key stays
// active.
func TestIssue26_U2_WriterErrorStopsActivation(t *testing.T) {
	r := newRig()
	r.run(t)
	r.clock.Add(policy.RotationPeriod + 1)
	r.run(t)
	r.clock.Add(policy.PublishDelay)
	r.events.AuditErr = errors.New("audit down")
	if err := r.mgr.Run(context.Background()); err == nil {
		t.Fatal("the pass must fail")
	}
	ks, _ := r.repo.List(context.Background())
	if got := states(ks); len(got) != 2 || got[0] != "active" || got[1] != "pending" {
		t.Fatalf("states = %v, want the old key active", got)
	}
}

// Issue26_U7: a forced rotation writes the delete entries, the create entry, and
// the force_rotate entry with the new kid. The origin is cli.
func TestIssue26_U7_ForceRotateEntries(t *testing.T) {
	r, ins := realWriterRig(t)
	old := r.run(t)[0]
	if err := r.mgr.ForceRotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ks, _ := r.repo.List(context.Background())
	if len(ks) != 1 || ks[0].KID == old.KID {
		t.Fatalf("keys = %+v", ks)
	}
	evs := events(t, ins)[1:] // The first entry is the create entry of the first pass.
	got := actions(evs)
	want := []string{keys.ActionDelete, keys.ActionCreate, keys.ActionForceRotate}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("actions = %v, want %v", got, want)
	}
	for _, e := range evs {
		if e.Actor != "identity" || e.ActorType != "service" || e.Data.Details["origin"] != "cli" {
			t.Fatalf("entry = %+v", e)
		}
	}
	if evs[0].Data.Details["forced"] != true || evs[0].Data.Target.ID != old.KID {
		t.Fatalf("delete entry = %+v", evs[0].Data)
	}
	if evs[2].Data.Details["newKid"] != ks[0].KID || evs[2].Data.Target.ID != ks[0].KID || evs[2].Data.Details["deletedKeys"] != float64(1) {
		t.Fatalf("force_rotate entry = %+v", evs[2].Data)
	}
	if names := r.store.Names(); len(names) != 1 || names[0] != domain.PrivateKeyName(ks[0].KID) {
		t.Fatalf("secrets = %v", names)
	}
}

// Issue26_U8: a writer error stops the forced rotation. The old keys stay. The
// next pass deletes the new secret that has no row.
func TestIssue26_U8_ForceRotateWriterError(t *testing.T) {
	r := newRig()
	old := r.run(t)[0]
	r.events.AuditErr = errors.New("audit down")
	if err := r.mgr.ForceRotate(context.Background()); err == nil {
		t.Fatal("the rotation must fail")
	}
	ks, _ := r.repo.List(context.Background())
	if len(ks) != 1 || ks[0].KID != old.KID || ks[0].State != domain.KeyActive {
		t.Fatalf("keys = %+v, want the old key", ks)
	}
	r.events.AuditErr = nil
	r.run(t)
	if names := r.store.Names(); len(names) != 1 || names[0] != domain.PrivateKeyName(old.KID) {
		t.Fatalf("secrets = %v, want the secret of the old key only", names)
	}
}

// A manager with no audit writer changes no key.
func TestIssue26_ManagerWithoutAuditChangesNothing(t *testing.T) {
	r := newRig()
	m := keys.NewManager(r.repo, r.store, policy, keys.WithClock(r.clock.Now))
	if err := m.Run(context.Background()); !errors.Is(err, keys.ErrNoAudit) {
		t.Fatalf("err = %v, want ErrNoAudit", err)
	}
	if ks, _ := r.repo.List(context.Background()); len(ks) != 0 {
		t.Fatalf("keys = %+v", ks)
	}
}

// Issue26_R9: a failed delete of an old secret after the commit is not an error
// of the rotation. The rotation is done, the entries are written, and the next
// pass deletes the old secret.
func TestIssue26_R9_ForceRotateSecretDeleteFails(t *testing.T) {
	r := newRig()
	old := r.run(t)[0]
	r.store.DeleteHook = func(string) error { return errors.New("delete failed") }
	if err := r.mgr.ForceRotate(context.Background()); err != nil {
		t.Fatalf("err = %v, want no error after the commit", err)
	}
	ks, _ := r.repo.List(context.Background())
	if len(ks) != 1 || ks[0].KID == old.KID {
		t.Fatalf("keys = %+v, want one new key", ks)
	}
	r.store.DeleteHook = nil
	r.run(t)
	if names := r.store.Names(); len(names) != 1 || names[0] != domain.PrivateKeyName(ks[0].KID) {
		t.Fatalf("secrets = %v, want the secret of the new key only", names)
	}
}
