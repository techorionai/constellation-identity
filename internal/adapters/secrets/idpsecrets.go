package secrets

import (
	"context"
	"errors"
	"fmt"

	platformsecrets "github.com/techorionai/constellation-platform-go/secrets"

	"github.com/techorionai/constellation-identity/internal/ports/idpsecrets"
)

// IdpSecrets keeps the client secrets of the upstream providers in the secrets
// service, under the name identity/idp/<provider>/client-secret.
type IdpSecrets struct {
	svc *platformsecrets.Service
}

var _ idpsecrets.Store = (*IdpSecrets)(nil)

// NewIdpSecrets makes the store.
func NewIdpSecrets(svc *platformsecrets.Service) *IdpSecrets { return &IdpSecrets{svc: svc} }

func secretName(provider string) string { return "identity/idp/" + provider + "/client-secret" }

// ClientSecret returns the secret of a provider. It returns an error that wraps
// idpsecrets.ErrNotFound if there is none.
func (s *IdpSecrets) ClientSecret(ctx context.Context, provider string) (string, error) {
	v, err := s.svc.Get(ctx, secretName(provider))
	if errors.Is(err, platformsecrets.ErrNotFound) {
		return "", fmt.Errorf("%s: %w", provider, idpsecrets.ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("get the client secret: %w", err)
	}
	return string(v), nil
}

// PutClientSecret stores the secret of a provider.
func (s *IdpSecrets) PutClientSecret(ctx context.Context, provider, secret string) error {
	if err := s.svc.Put(ctx, secretName(provider), []byte(secret)); err != nil {
		return fmt.Errorf("store the client secret: %w", err)
	}
	return nil
}
