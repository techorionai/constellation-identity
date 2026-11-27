package services

import (
	"context"
	"fmt"
	"log/slog"

	clientpg "github.com/techorionai/constellation-platform-go/clients/postgres"
	platformsecrets "github.com/techorionai/constellation-platform-go/secrets"
	secretspg "github.com/techorionai/constellation-platform-go/secrets/postgres"
	transactionpg "github.com/techorionai/constellation-platform-go/transaction/postgres"

	"github.com/techorionai/constellation-identity/internal/adapters/postgres"
	adaptersecrets "github.com/techorionai/constellation-identity/internal/adapters/secrets"
	"github.com/techorionai/constellation-identity/internal/app/keys"
	"github.com/techorionai/constellation-identity/internal/config"
)

// ForceRotateSigningKeys deletes all signing keys and their secrets, and makes
// one new active key. All tokens that the old keys signed become invalid. It
// runs the migrations first, so that it works on an empty database too.
func ForceRotateSigningKeys(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	db, err := clientpg.New(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer db.Close()
	if err := RunMigrations(ctx, db); err != nil {
		return err
	}
	ring, err := platformsecrets.NewKeyRing(cfg.Secrets)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	store := adaptersecrets.New(platformsecrets.NewService(ring, secretspg.NewRepository(db.Pool)))
	w, err := newAuditWriter()
	if err != nil {
		return err
	}
	// The command writes only the audit outbox row. The relay of a running
	// service publishes it.
	mgr := keys.NewManager(postgres.NewSigningKeys(db.Pool), store, cfg.Keys.Policy(), keys.WithLogger(log),
		keys.WithAudit(transactionpg.NewTransactor(db.Pool), w))
	return mgr.ForceRotate(ctx)
}
