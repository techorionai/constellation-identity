package services

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/techorionai/constellation-platform-go/audit"
	auditpg "github.com/techorionai/constellation-platform-go/audit/postgres"
	clientvk "github.com/techorionai/constellation-platform-go/clients/valkey"
	"github.com/techorionai/constellation-platform-go/outbox"
	outboxpg "github.com/techorionai/constellation-platform-go/outbox/postgres"
	retentionpg "github.com/techorionai/constellation-platform-go/retention/postgres"
	"github.com/techorionai/constellation-platform-go/streams"
	streamsvk "github.com/techorionai/constellation-platform-go/streams/valkey"
	"github.com/techorionai/constellation-platform-go/transaction"

	"github.com/techorionai/constellation-platform-go/retention"
)

// AuditApp is the app name of the identity service in its audit entries. The
// own client ID of the service is the same value.
const AuditApp = "identity"

// newAuditWriter makes the audit writer of the identity service.
func newAuditWriter() (*audit.EntryWriter, error) {
	w, err := audit.New(auditpg.NewInserter(), audit.Config{App: AuditApp, ClientID: AuditApp})
	if err != nil {
		return nil, fmt.Errorf("make the audit writer: %w", err)
	}
	return w, nil
}

// newAuditRelay makes the relay that moves the rows of the audit outbox to the
// Valkey stream audit.stream:identity.
func newAuditRelay(pool *pgxpool.Pool, kv *clientvk.Client) (*outbox.Relay, error) {
	store, err := outboxpg.NewStoreFor(pool, auditpg.Table)
	if err != nil {
		return nil, fmt.Errorf("make the audit outbox store: %w", err)
	}
	relay, err := outbox.NewRelay(store, streamsvk.NewPublisher(kv.Raw, AuditApp, streamsvk.WithFamily(streams.Audit)),
		outbox.RelayOptions{Name: "audit"})
	if err != nil {
		return nil, fmt.Errorf("make the audit relay: %w", err)
	}
	return relay, nil
}

// notifyWriter writes the audit entries with the inner writer and wakes the
// relay after the transaction commits. The relay also polls, so a missed wake
// delays the entry only.
type notifyWriter struct {
	inner audit.Writer
	tx    transaction.Transactor
	relay *outbox.Relay
}

var _ audit.Writer = notifyWriter{}

// Write writes the entries in the transaction of the context.
func (w notifyWriter) Write(ctx context.Context, entries ...audit.Entry) error {
	if err := w.inner.Write(ctx, entries...); err != nil {
		return err
	}
	w.tx.AfterCommit(ctx, func(context.Context) { w.relay.Notify() })
	return nil
}

// auditRetentionJobs returns the retention jobs of the audit outbox table and
// of the audit stream.
func auditRetentionJobs(pool *pgxpool.Pool, kv *clientvk.Client, outboxCfg, streamCfg retention.Config, defaultPeriod time.Duration) ([]retention.Job, error) {
	outboxPurger, err := retentionpg.NewTablePurger(pool, retentionpg.TableSpec{Table: auditpg.Table, TimeColumn: "published_at"})
	if err != nil {
		return nil, fmt.Errorf("make the audit outbox purger: %w", err)
	}
	return []retention.Job{
		{Name: "audit_outbox", Config: outboxCfg, DefaultPeriod: defaultPeriod, Purger: outboxPurger},
		{Name: "audit_stream", Config: streamCfg, DefaultPeriod: defaultPeriod,
			Purger: streamsvk.NewTrimPurger(kv.Raw, AuditApp, streamsvk.WithFamily(streams.Audit))},
	}, nil
}
