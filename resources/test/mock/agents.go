package mock

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/agentroles"
	"github.com/techorionai/constellation-identity/internal/ports/agents"
)

// Agents is an in-memory agent repository.
type Agents struct {
	mu   sync.Mutex
	Rows map[string]domain.Agent
	// GetCalls counts the calls of Get.
	GetCalls int
}

var _ agents.Repository = (*Agents)(nil)

// NewAgents makes an empty repository.
func NewAgents() *Agents { return &Agents{Rows: map[string]domain.Agent{}} }

func (r *Agents) nameTaken(id, name string) bool {
	for _, a := range r.Rows {
		if a.Name == name && a.ID != id {
			return true
		}
	}
	return false
}

// Create adds an agent.
func (r *Agents) Create(_ context.Context, a domain.Agent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nameTaken(a.ID, a.Name) {
		return agents.ErrNameTaken
	}
	r.Rows[a.ID] = a
	return nil
}

// Get returns an agent.
func (r *Agents) Get(_ context.Context, id string) (domain.Agent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.GetCalls++
	a, ok := r.Rows[id]
	if !ok {
		return domain.Agent{}, fmt.Errorf("agent %s: %w", id, agents.ErrNotFound)
	}
	return a, nil
}

// Update writes an agent.
func (r *Agents) Update(_ context.Context, a domain.Agent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.Rows[a.ID]; !ok {
		return fmt.Errorf("agent %s: %w", a.ID, agents.ErrNotFound)
	}
	if r.nameTaken(a.ID, a.Name) {
		return agents.ErrNameTaken
	}
	r.Rows[a.ID] = a
	return nil
}

// List returns a page of agents.
func (r *Agents) List(_ context.Context, after *domain.PageCursor, limit int) ([]domain.Agent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	all := make([]domain.Agent, 0, len(r.Rows))
	for _, a := range r.Rows {
		all = append(all, a)
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.Before(all[j].CreatedAt)
		}
		return all[i].ID < all[j].ID
	})
	var out []domain.Agent
	for _, a := range all {
		if after != nil && !a.CreatedAt.After(after.CreatedAt) && (!a.CreatedAt.Equal(after.CreatedAt) || a.ID <= after.ID) {
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, a)
	}
	return out, nil
}

// AgentRoles is an in-memory repository of the role assignments of agents.
type AgentRoles struct {
	mu   sync.Mutex
	Rows map[string][]domain.RoleRef
	// Perms gives the permissions of a role. A role with no entry is pending.
	Perms map[domain.RoleRef][]string
}

var _ agentroles.Repository = (*AgentRoles)(nil)

// NewAgentRoles makes an empty repository.
func NewAgentRoles() *AgentRoles {
	return &AgentRoles{Rows: map[string][]domain.RoleRef{}, Perms: map[domain.RoleRef][]string{}}
}

// Assignments returns the assignments of an agent.
func (r *AgentRoles) Assignments(_ context.Context, agentID string) ([]domain.RoleAssignment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.RoleAssignment
	for _, ref := range r.Rows[agentID] {
		_, known := r.Perms[ref]
		out = append(out, domain.RoleAssignment{Role: ref, Source: domain.AssignmentAPI, Pending: !known})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role.String() < out[j].Role.String() })
	return out, nil
}

// Page returns a page of the assignments of an agent.
func (r *AgentRoles) Page(ctx context.Context, agentID string, after *domain.RoleRef, limit int) ([]domain.RoleAssignment, error) {
	all, _ := r.Assignments(ctx, agentID)
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

// GrantedPermissions returns the permissions of the roles of an agent. A
// pending role gives none.
func (r *AgentRoles) GrantedPermissions(_ context.Context, agentID string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, ref := range r.Rows[agentID] {
		for _, p := range r.Perms[ref] {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// Assign gives a role.
func (r *AgentRoles) Assign(_ context.Context, agentID string, role domain.RoleRef, _ domain.AssignmentSource) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(r.Rows[agentID], role) {
		r.Rows[agentID] = append(r.Rows[agentID], role)
	}
	return nil
}

// Delete removes a role.
func (r *AgentRoles) Delete(_ context.Context, agentID string, role domain.RoleRef) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := slices.Index(r.Rows[agentID], role)
	if i < 0 {
		return false, nil
	}
	r.Rows[agentID] = slices.Delete(r.Rows[agentID], i, i+1)
	return true, nil
}
