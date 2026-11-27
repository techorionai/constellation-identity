// Package commands holds the write use cases.
package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/techorionai/constellation-platform-go/audit"
	"github.com/techorionai/constellation-platform-go/executor"
	"github.com/techorionai/constellation-platform-go/transaction"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/clientroles"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
)

// SyncClients is the input of the clients file sync.
type SyncClients struct {
	// Clients are the clients of the file.
	Clients []domain.ClientConfig
}

// SyncClientsCommand writes the clients of the clients file to the database.
type SyncClientsCommand struct {
	repo  clients.Repository
	log   *slog.Logger
	tx    transaction.Transactor
	audit audit.Writer
	roles clientroles.Repository
}

var _ executor.Executor[SyncClients] = (*SyncClientsCommand)(nil)

// NewSyncClients makes the command.
func NewSyncClients(repo clients.Repository, log *slog.Logger) *SyncClientsCommand {
	if log == nil {
		log = slog.Default()
	}
	return &SyncClientsCommand{repo: repo, log: log}
}

// WithAudit sets the transactor, the audit writer, and the repository of the
// client roles. Each client that the sync adds or changes writes one audit entry
// in the transaction of the change. A sync that changes nothing writes no
// entry. Without the transactor, the sync gives ErrNoAuditWriter.
func (c *SyncClientsCommand) WithAudit(tx transaction.Transactor, w audit.Writer, roles clientroles.Repository) *SyncClientsCommand {
	c.tx, c.audit, c.roles = tx, w, roles
	return c
}

// Execute upserts each client of the file with source config, under the
// cluster lock. A config client that is not in the file is set to disabled. A
// client with source api is not changed.
func (c *SyncClientsCommand) Execute(ctx context.Context, p SyncClients) error {
	if c.tx == nil || c.audit == nil {
		return ErrNoAuditWriter
	}
	return c.repo.WithLock(ctx, func(ctx context.Context) error {
		ids := make([]string, 0, len(p.Clients))
		for _, cc := range p.Clients {
			if err := c.upsert(ctx, cc); err != nil {
				return err
			}
			ids = append(ids, cc.Client.ID)
		}
		var disabled []string
		err := c.within(ctx, func(ctx context.Context) error {
			var err error
			if disabled, err = c.repo.DisableConfigNotIn(ctx, ids); err != nil {
				return err
			}
			for _, id := range disabled {
				if err := c.write(ctx, id, []string{"disabled"}, true); err != nil {
					return err
				}
			}
			return nil
		}, "disable_config_clients")
		if err != nil {
			return err
		}
		for _, id := range disabled {
			c.log.InfoContext(ctx, "client removed from the clients file is disabled", "client_id", id)
		}
		return nil
	})
}

// within runs fn in a transaction.
func (c *SyncClientsCommand) within(ctx context.Context, fn func(ctx context.Context) error, name string) error {
	return c.tx.WithinTx(ctx, fn, txName(name))
}

// write writes the entry of a sync change. If the fields have disabled, the
// details also have the new state (disabled), so that a reader can tell a
// disable from an enable.
func (c *SyncClientsCommand) write(ctx context.Context, id string, fields []string, disabled bool) error {
	if len(fields) == 0 {
		return nil
	}
	details := map[string]any{"fields": fields}
	if slices.Contains(fields, "disabled") {
		details["disabled"] = disabled
	}
	return writeAudit(ctx, c.audit, time.Now().UTC(), ActionClientSync, targetClient, id, details)
}

func (c *SyncClientsCommand) upsert(ctx context.Context, cc domain.ClientConfig) error {
	return c.within(ctx, func(ctx context.Context) error {
		fields, err := c.diff(ctx, cc)
		if err != nil {
			return err
		}
		applied, err := c.repo.UpsertConfig(ctx, cc)
		if err != nil {
			return err
		}
		if !applied {
			c.log.WarnContext(ctx, "client in the clients file has the same ID as an api client and is ignored", "client_id", cc.Client.ID)
			return nil
		}
		return c.write(ctx, cc.Client.ID, fields, false)
	}, "sync_client")
}

// diff returns the names of the fields that the sync changes. A new client has
// all fields.
func (c *SyncClientsCommand) diff(ctx context.Context, cc domain.ClientConfig) ([]string, error) {
	old, err := c.repo.Get(ctx, cc.Client.ID)
	if errors.Is(err, clients.ErrNotFound) {
		return []string{"name", "type", "app", "redirectUris", "postLogoutRedirectUris", "keys", "roles"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get the client: %w", err)
	}
	if old.Source != domain.SourceConfig {
		return nil, nil
	}
	var fields []string
	if old.Name != cc.Client.Name {
		fields = append(fields, "name")
	}
	if old.Type != cc.Client.Type {
		fields = append(fields, "type")
	}
	if old.App != cc.Client.App {
		fields = append(fields, "app")
	}
	if old.Disabled {
		fields = append(fields, "disabled")
	}
	if !sameSet(old.RedirectURIs, cc.Client.RedirectURIs) {
		fields = append(fields, "redirectUris")
	}
	if !sameSet(old.PostLogoutRedirectURIs, cc.Client.PostLogoutRedirectURIs) {
		fields = append(fields, "postLogoutRedirectUris")
	}
	keys, err := c.repo.Keys(ctx, cc.Client.ID)
	if err != nil {
		return nil, fmt.Errorf("get the keys: %w", err)
	}
	if !sameKeys(keys, cc.Keys) {
		fields = append(fields, "keys")
	}
	if c.roles != nil {
		got, err := c.roles.Assignments(ctx, cc.Client.ID)
		if err != nil {
			return nil, fmt.Errorf("get the roles: %w", err)
		}
		var have []string
		for _, a := range got {
			if a.Source == domain.AssignmentConfig {
				have = append(have, a.Role.String())
			}
		}
		want := make([]string, 0, len(cc.Roles))
		for _, r := range cc.Roles {
			want = append(want, r.String())
		}
		if !sameSet(have, want) {
			fields = append(fields, "roles")
		}
	}
	return fields, nil
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

func sameKeys(have, want []domain.ClientKey) bool {
	enc := func(ks []domain.ClientKey) []string {
		out := make([]string, 0, len(ks))
		for _, k := range ks {
			j, _ := json.Marshal(k.PublicJWK)
			out = append(out, k.KID+"|"+string(j))
		}
		return out
	}
	return sameSet(enc(have), enc(want))
}
