package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	clientpg "github.com/techorionai/constellation-platform-go/clients/postgres"
	platformsecrets "github.com/techorionai/constellation-platform-go/secrets"
	secretspg "github.com/techorionai/constellation-platform-go/secrets/postgres"

	adapteroidc "github.com/techorionai/constellation-identity/internal/adapters/oidc"
	adaptersecrets "github.com/techorionai/constellation-identity/internal/adapters/secrets"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/idpsecrets"
)

// ErrIdpSecretMissing means a provider is on and its client secret is not in
// the secrets store.
var ErrIdpSecretMissing = errors.New("the client secret of a provider is missing")

// buildIdpClient makes the adapter of the upstream providers. It reads the
// client secret of each provider that is on from the secrets store. If a secret
// is missing, it logs the error identity.idp.secret_missing with the provider
// name, and the service does not start.
func (a *App) buildIdpClient(o options, providers []string) (*adapteroidc.Client, error) {
	cfg := a.cfg
	store := adaptersecrets.NewIdpSecrets(a.secrets)
	ic := adapteroidc.Config{Issuer: cfg.Issuer, HTTPTimeout: cfg.IDP.HTTPTimeout, Now: o.clock, Transport: o.idpTransport, Log: a.log}
	for _, p := range providers {
		secret, err := store.ClientSecret(context.Background(), p)
		if errors.Is(err, idpsecrets.ErrNotFound) {
			a.log.Error("identity.idp.secret_missing: the client secret of a provider is not stored. Run identity set-idp-secret",
				"event", "identity.idp.secret_missing", "provider", p)
			return nil, fmt.Errorf("%w: %s", ErrIdpSecretMissing, p)
		}
		if err != nil {
			return nil, fmt.Errorf("read the client secret of %s: %w", p, err)
		}
		switch p {
		case domain.ProviderGoogle:
			ic.Google = adapteroidc.ProviderConfig{
				ClientID: cfg.IDP.Google.ClientID, ClientSecret: secret, AllowedDomains: cfg.IDP.Google.AllowedDomains,
			}
		case domain.ProviderMicrosoft:
			ic.Microsoft = adapteroidc.ProviderConfig{
				ClientID: cfg.IDP.Microsoft.ClientID, ClientSecret: secret, Tenant: cfg.IDP.Microsoft.Tenant,
			}
		}
	}
	return adapteroidc.New(ic), nil
}

// warnUsersWithoutLoginMethod counts the active users that have no login method
// and logs the warning identity.idp.users_without_login_method with the count.
// A provider or passkeys that are off can leave users locked out. A failure of
// the count is logged and does not stop the start.
func (a *App) warnUsersWithoutLoginMethod(ctx context.Context, st *userStack) {
	n, err := st.links.CountUsersWithoutLoginMethod(ctx, st.providers, st.passkeysOn)
	if err != nil {
		a.log.WarnContext(ctx, "identity.idp.count_failed", "event", "identity.idp.count_failed", "error", err)
		return
	}
	if n > 0 {
		a.log.WarnContext(ctx, "identity.idp.users_without_login_method: active users have no login method. Link the users or set passwords",
			"event", "identity.idp.users_without_login_method", "count", n)
	}
}

// SetIdpSecret stores the client secret of a provider in the secrets store. It
// runs the migrations first. It never logs the secret. It returns an error for
// a provider name that is not valid.
func SetIdpSecret(ctx context.Context, cfg config.Config, provider, secret string, log *slog.Logger) error {
	if !domain.ValidProvider(provider) {
		return fmt.Errorf("the provider %q is not valid", provider)
	}
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
	svc := platformsecrets.NewService(ring, secretspg.NewRepository(db.Pool))
	if err := adaptersecrets.NewIdpSecrets(svc).PutClientSecret(ctx, provider, secret); err != nil {
		return err
	}
	log.InfoContext(ctx, "identity.idp.secret_stored", "event", "identity.idp.secret_stored", "provider", provider)
	return nil
}
