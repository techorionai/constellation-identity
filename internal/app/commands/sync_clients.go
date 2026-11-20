// Package commands holds the write use cases.
package commands

import (
	"context"
	"log/slog"

	"github.com/techorionai/constellation-platform-go/executor"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
)

// SyncClients is the input of the clients file sync.
type SyncClients struct {
	// Clients are the clients of the file.
	Clients []domain.ClientConfig
}

// SyncClientsCommand writes the clients of the clients file to the database.
type SyncClientsCommand struct {
	repo clients.Repository
	log  *slog.Logger
}

var _ executor.Executor[SyncClients] = (*SyncClientsCommand)(nil)

// NewSyncClients makes the command.
func NewSyncClients(repo clients.Repository, log *slog.Logger) *SyncClientsCommand {
	if log == nil {
		log = slog.Default()
	}
	return &SyncClientsCommand{repo: repo, log: log}
}

// Execute upserts each client of the file with source config, under the
// cluster lock. A config client that is not in the file is set to disabled. A
// client with source api is not changed.
func (c *SyncClientsCommand) Execute(ctx context.Context, p SyncClients) error {
	return c.repo.WithLock(ctx, func(ctx context.Context) error {
		ids := make([]string, 0, len(p.Clients))
		for _, cc := range p.Clients {
			applied, err := c.repo.UpsertConfig(ctx, cc)
			if err != nil {
				return err
			}
			if !applied {
				c.log.WarnContext(ctx, "client in the clients file has the same ID as an api client and is ignored", "client_id", cc.Client.ID)
			}
			ids = append(ids, cc.Client.ID)
		}
		disabled, err := c.repo.DisableConfigNotIn(ctx, ids)
		if err != nil {
			return err
		}
		for _, id := range disabled {
			c.log.InfoContext(ctx, "client removed from the clients file is disabled", "client_id", id)
		}
		return nil
	})
}
