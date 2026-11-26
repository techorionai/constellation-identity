package mock

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// List returns a page of users in order of the creation time and the ID.
func (r *Users) List(_ context.Context, after *domain.PageCursor, limit int) ([]domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	all := make([]domain.User, 0, len(r.Rows))
	for _, u := range r.Rows {
		all = append(all, u)
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.Before(all[j].CreatedAt)
		}
		return all[i].ID < all[j].ID
	})
	var out []domain.User
	for _, u := range all {
		if after != nil && (u.CreatedAt.Before(after.CreatedAt) || u.CreatedAt.Equal(after.CreatedAt) && u.ID <= after.ID) {
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, u)
	}
	return out, nil
}

// SetName sets the name.
func (r *Users) SetName(_ context.Context, id, name string, _ time.Time) error {
	return r.change(id, func(u *domain.User) { u.Name = name })
}

// GetByID returns a session.
func (r *Sessions) GetByID(_ context.Context, id string) (domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.Rows[id]; ok {
		return s, nil
	}
	return domain.Session{}, sessions.ErrNotFound
}

// ListByUser returns the valid sessions of a user.
func (r *Sessions) ListByUser(_ context.Context, userID string, now time.Time, after *domain.PageCursor, limit int) ([]domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var all []domain.Session
	for _, s := range r.Rows {
		if s.UserID == userID && s.Valid(now) {
			all = append(all, s)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.Before(all[j].CreatedAt)
		}
		return all[i].ID < all[j].ID
	})
	var out []domain.Session
	for _, s := range all {
		if after != nil && (s.CreatedAt.Before(after.CreatedAt) || s.CreatedAt.Equal(after.CreatedAt) && s.ID <= after.ID) {
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, s)
	}
	return out, nil
}

// Reauthenticate replaces the token hash of a valid session of the user.
func (r *Sessions) Reauthenticate(_ context.Context, a sessions.Reauth) (string, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.Rows {
		if s.TokenHash == a.OldHash && s.UserID == a.UserID && s.Valid(a.Now) {
			s.TokenHash, s.AuthTime, s.LastSeenAt, s.IdleExpiresAt, s.AuthMethods = a.NewHash, a.Now, a.Now, a.IdleExpires, a.Methods
			s.UpstreamAuthValid = a.UpstreamAuthValid
			r.Rows[id] = s
			return id, true, nil
		}
	}
	return "", false, nil
}

// RevokeCascade revokes a session. The mock has no families.
func (r *Sessions) RevokeCascade(_ context.Context, id string, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.Rows[id]
	if !ok {
		return false, nil
	}
	if s.RevokedAt == nil {
		s.RevokedAt = &now
		r.Rows[id] = s
	}
	return true, nil
}

// RevokeAllOfUser revokes all sessions of a user.
func (r *Sessions) RevokeAllOfUser(_ context.Context, userID string, now time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, s := range r.Rows {
		if s.UserID == userID && s.RevokedAt == nil {
			s.RevokedAt = &now
			r.Rows[id] = s
			n++
		}
	}
	return n, nil
}

// Delete removes a role of a user.
func (r *UserRoles) Delete(_ context.Context, userID string, role domain.RoleRef) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := slices.Index(r.Rows[userID], role)
	if i < 0 {
		return false, nil
	}
	r.Rows[userID] = slices.Delete(r.Rows[userID], i, i+1)
	return true, nil
}

// Page returns a page of the assignments of a user.
func (r *UserRoles) Page(ctx context.Context, userID string, after *domain.RoleRef, limit int) ([]domain.RoleAssignment, error) {
	all, _ := r.Assignments(ctx, userID)
	sort.Slice(all, func(i, j int) bool { return all[i].Role.String() < all[j].Role.String() })
	var out []domain.RoleAssignment
	for _, a := range all {
		if after != nil && a.Role.String() <= after.String() {
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, a)
	}
	return out, nil
}

// GrantedPermissions returns the permissions of the roles of a user. The map
// Perms gives the permissions of a role. A role with no entry is pending. The
// implicit roles count like assigned roles.
func (r *UserRoles) GrantedPermissions(_ context.Context, userID string, implicit ...domain.RoleRef) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, ref := range append(slices.Clone(r.Rows[userID]), implicit...) {
		for _, p := range r.Perms[ref] {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// CountActiveHolders counts the active users with a role that grants the
// permission. A role with no entry in Perms is pending and does not count.
func (r *UserRoles) CountActiveHolders(_ context.Context, permission string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, refs := range r.Rows {
		u, ok := r.Users.Rows[id]
		if !ok || u.Status != domain.UserActive {
			continue
		}
		for _, ref := range refs {
			if slices.Contains(r.Perms[ref], permission) {
				n++
				break
			}
		}
	}
	return n, nil
}

var _ users.Repository = (*Users)(nil)
