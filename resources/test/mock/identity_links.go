package mock

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/identitylinks"
	"github.com/techorionai/constellation-identity/internal/ports/idpflow"
	"github.com/techorionai/constellation-identity/internal/ports/upstreamidp"
)

// IdentityLinks is an in-memory repository of the upstream links.
type IdentityLinks struct {
	mu   sync.Mutex
	Rows map[string]domain.IdentityLink
}

var _ identitylinks.Repository = (*IdentityLinks)(nil)

// NewIdentityLinks makes an empty repository.
func NewIdentityLinks() *IdentityLinks { return &IdentityLinks{Rows: map[string]domain.IdentityLink{}} }

// Create adds a link.
func (r *IdentityLinks) Create(_ context.Context, l domain.IdentityLink) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.Rows {
		if o.Provider == l.Provider && o.Subject == l.Subject {
			return identitylinks.ErrSubjectLinked
		}
		if o.UserID == l.UserID && o.Provider == l.Provider {
			return identitylinks.ErrProviderLinked
		}
	}
	r.Rows[l.ID] = l
	return nil
}

func (r *IdentityLinks) find(match func(domain.IdentityLink) bool) (domain.IdentityLink, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.Rows {
		if match(l) {
			return l, nil
		}
	}
	return domain.IdentityLink{}, fmt.Errorf("link: %w", identitylinks.ErrNotFound)
}

// GetBySubject returns the link of an upstream account.
func (r *IdentityLinks) GetBySubject(_ context.Context, provider, subject string) (domain.IdentityLink, error) {
	return r.find(func(l domain.IdentityLink) bool { return l.Provider == provider && l.Subject == subject })
}

// GetByUserProvider returns the link of a user for a provider.
func (r *IdentityLinks) GetByUserProvider(_ context.Context, userID, provider string) (domain.IdentityLink, error) {
	return r.find(func(l domain.IdentityLink) bool { return l.UserID == userID && l.Provider == provider })
}

// ListByUser returns the links of a user.
func (r *IdentityLinks) ListByUser(_ context.Context, userID string, after *domain.PageCursor, limit int) ([]domain.IdentityLink, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var all []domain.IdentityLink
	for _, l := range r.Rows {
		if l.UserID == userID {
			all = append(all, l)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.Before(all[j].CreatedAt)
		}
		return all[i].Provider < all[j].Provider
	})
	var out []domain.IdentityLink
	for _, l := range all {
		if after != nil && !l.CreatedAt.After(after.CreatedAt) && (!l.CreatedAt.Equal(after.CreatedAt) || l.Provider <= after.ID) {
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, l)
	}
	return out, nil
}

// Remove deletes the link of a user for a provider.
func (r *IdentityLinks) Remove(_ context.Context, userID, provider string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, l := range r.Rows {
		if l.UserID == userID && l.Provider == provider {
			delete(r.Rows, id)
			return nil
		}
	}
	return fmt.Errorf("link: %w", identitylinks.ErrNotFound)
}

// Touch sets the last use time and the email.
func (r *IdentityLinks) Touch(_ context.Context, id, email string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l, ok := r.Rows[id]; ok {
		l.LastUsedAt, l.Email = &now, email
		r.Rows[id] = l
	}
	return nil
}

// CountUsersWithoutLoginMethod is not used by the mock users.
func (r *IdentityLinks) CountUsersWithoutLoginMethod(context.Context, []string, bool) (int, error) {
	return 0, nil
}

// IdpFlows is an in-memory store of the flow records.
type IdpFlows struct {
	mu   sync.Mutex
	Rows map[string]domain.IdpFlow
}

var _ idpflow.Store = (*IdpFlows)(nil)

// NewIdpFlows makes an empty store.
func NewIdpFlows() *IdpFlows { return &IdpFlows{Rows: map[string]domain.IdpFlow{}} }

// Put stores a record.
func (s *IdpFlows) Put(_ context.Context, hash string, f domain.IdpFlow, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Rows[hash] = f
	return nil
}

// Take reads and deletes a record.
func (s *IdpFlows) Take(_ context.Context, hash string) (domain.IdpFlow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.Rows[hash]
	if !ok {
		return domain.IdpFlow{}, idpflow.ErrNotFound
	}
	delete(s.Rows, hash)
	return f, nil
}

// IdpClient is a fake upstream provider client.
type IdpClient struct {
	On map[string]bool
	// AuthURL is the result of AuthCodeURL. AuthErr is its error.
	AuthURL string
	AuthErr error
	// Last holds the parameters of the last call of AuthCodeURL.
	Last upstreamidp.AuthParams
	// Identity and ExchangeErr are the result of Exchange.
	Identity    domain.UpstreamIdentity
	ExchangeErr error
}

var _ upstreamidp.Client = (*IdpClient)(nil)

// Enabled reports whether the provider is on.
func (c *IdpClient) Enabled(p string) bool { return c.On[p] }

// AuthCodeURL returns the fake URL.
func (c *IdpClient) AuthCodeURL(_ context.Context, _ string, p upstreamidp.AuthParams) (string, error) {
	c.Last = p
	return c.AuthURL, c.AuthErr
}

// Exchange returns the fake identity.
func (c *IdpClient) Exchange(_ context.Context, provider string, _ upstreamidp.ExchangeParams) (domain.UpstreamIdentity, error) {
	id := c.Identity
	id.Provider = provider
	return id, c.ExchangeErr
}
