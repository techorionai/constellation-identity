package mock

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/apitokens"
)

// APITokens is an in-memory repository of personal API tokens.
type APITokens struct {
	mu sync.Mutex
	// Rows holds the tokens by hash.
	Rows map[string]domain.APIToken
	// Users gives the status of the owner.
	Users *Users
	// GetErr is returned by GetByHash when it is set.
	GetErr error
	// TouchErr is returned by TouchLastUsed when it is set.
	TouchErr error
	// Lookups counts the calls of GetByHash.
	Lookups int
}

var _ apitokens.Repository = (*APITokens)(nil)

// NewAPITokens makes an empty repository.
func NewAPITokens(u *Users) *APITokens {
	return &APITokens{Rows: map[string]domain.APIToken{}, Users: u}
}

// Insert adds a token.
func (r *APITokens) Insert(_ context.Context, hash string, t domain.APIToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.Rows[hash]; ok {
		return errors.New("duplicate hash")
	}
	r.Rows[hash] = t
	return nil
}

// CountActive counts the active tokens of a user.
func (r *APITokens) CountActive(_ context.Context, userID string, now time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, t := range r.Rows {
		if t.UserID == userID && t.RevokedAt == nil && t.ExpiresAt.After(now) {
			n++
		}
	}
	return n, nil
}

// CountAll counts all tokens of a user.
func (r *APITokens) CountAll(_ context.Context, userID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, t := range r.Rows {
		if t.UserID == userID {
			n++
		}
	}
	return n, nil
}

// ListByUser returns the tokens of a user, newest first.
func (r *APITokens) ListByUser(_ context.Context, userID string, after *domain.PageCursor, limit int) ([]domain.APIToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var all []domain.APIToken
	for _, t := range r.Rows {
		if t.UserID == userID {
			all = append(all, t)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.After(all[j].CreatedAt)
		}
		return all[i].ID > all[j].ID
	})
	var out []domain.APIToken
	for _, t := range all {
		if after != nil {
			older := t.CreatedAt.Before(after.CreatedAt) || t.CreatedAt.Equal(after.CreatedAt) && t.ID < after.ID
			if !older {
				continue
			}
		}
		if len(out) == limit {
			break
		}
		out = append(out, t)
	}
	return out, nil
}

// GetByHash returns a token and the status of its user.
func (r *APITokens) GetByHash(_ context.Context, hash string) (domain.APITokenWithOwner, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Lookups++
	if r.GetErr != nil {
		return domain.APITokenWithOwner{}, r.GetErr
	}
	t, ok := r.Rows[hash]
	if !ok {
		return domain.APITokenWithOwner{}, fmt.Errorf("get: %w", apitokens.ErrNotFound)
	}
	return domain.APITokenWithOwner{APIToken: t, OwnerStatus: r.Users.Rows[t.UserID].Status}, nil
}

// Revoke sets revoked_at.
func (r *APITokens) Revoke(_ context.Context, id, owner string, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for h, t := range r.Rows {
		if t.ID == id && (owner == "" || t.UserID == owner) {
			if t.RevokedAt == nil {
				t.RevokedAt = &now
				r.Rows[h] = t
			}
			return true, nil
		}
	}
	return false, nil
}

// RevokeAllOfUser revokes the active tokens of a user.
func (r *APITokens) RevokeAllOfUser(_ context.Context, userID string, now time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for h, t := range r.Rows {
		if t.UserID == userID && t.RevokedAt == nil && t.ExpiresAt.After(now) {
			t.RevokedAt = &now
			r.Rows[h] = t
			n++
		}
	}
	return n, nil
}

// TouchLastUsed sets last_used_at.
func (r *APITokens) TouchLastUsed(_ context.Context, id string, now time.Time, interval time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.TouchErr != nil {
		return r.TouchErr
	}
	for h, t := range r.Rows {
		if t.ID == id && (t.LastUsedAt == nil || t.LastUsedAt.Before(now.Add(-interval))) {
			t.LastUsedAt = &now
			r.Rows[h] = t
		}
	}
	return nil
}
