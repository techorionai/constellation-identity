package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/agents"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
)

// Problems of the agent operations.
func errAgentNotFound() error {
	return apperrors.NewProblem(404, "agent_not_found", "The agent does not exist.")
}

func errAgentNameTaken() error {
	return apperrors.NewConflictCode("agent_name_taken", "An agent has this name.")
}

func errAgentName() error {
	return apperrors.NewInvalidInput("the name must have 1 to 100 characters and no control character")
}

// agentNow returns the time with the precision of the database, so that the
// time in a page cursor compares correctly with a stored time.
func (a *Admin) agentNow() time.Time { return a.now().Truncate(time.Microsecond) }

// getAgent returns an agent. An ID that is not a UUID gives agent_not_found
// before the query.
func (a *Admin) getAgent(ctx context.Context, id string) (domain.Agent, error) {
	if !uuidPattern.MatchString(id) {
		return domain.Agent{}, errAgentNotFound()
	}
	ag, err := a.d.Agents.Get(ctx, id)
	if errors.Is(err, agents.ErrNotFound) {
		return domain.Agent{}, errAgentNotFound()
	}
	if err != nil {
		return domain.Agent{}, fmt.Errorf("get the agent: %w", err)
	}
	return ag, nil
}

// ListAgents returns a page of agents.
func (a *Admin) ListAgents(ctx context.Context, p ListPage) (Page[domain.Agent], error) {
	n, err := p.size()
	if err != nil {
		return Page[domain.Agent]{}, err
	}
	cur, err := decodeUUIDCursor(p.Token)
	if err != nil {
		return Page[domain.Agent]{}, err
	}
	items, err := a.d.Agents.List(ctx, cur, n+1)
	if err != nil {
		return Page[domain.Agent]{}, fmt.Errorf("list agents: %w", err)
	}
	out := Page[domain.Agent]{Items: items}
	if len(items) > n {
		out.Items = items[:n]
		last := out.Items[n-1]
		out.Next = EncodeTimeCursor(last.CreatedAt, last.ID)
	}
	return out, nil
}

// GetAgent returns an agent.
func (a *Admin) GetAgent(ctx context.Context, id string) (domain.Agent, error) {
	return a.getAgent(ctx, id)
}

// CreateAgent makes an agent for a service client. A disabled client is
// allowed, because client authentication refuses it at the exchange.
func (a *Admin) CreateAgent(ctx context.Context, actor, name, clientID string) (domain.Agent, error) {
	n, err := domain.CheckAgentName(name)
	if err != nil {
		return domain.Agent{}, errAgentName()
	}
	c, err := a.d.Clients.Get(ctx, clientID)
	if errors.Is(err, clients.ErrNotFound) {
		return domain.Agent{}, apperrors.NewUnprocessable("client_not_found", "The client does not exist.")
	}
	if err != nil {
		return domain.Agent{}, fmt.Errorf("get the client: %w", err)
	}
	if c.Type != domain.ClientTypeService {
		return domain.Agent{}, apperrors.NewUnprocessable("client_not_service", "The client is not a service client.")
	}
	now := a.agentNow()
	ag := domain.Agent{ID: newUUID(), Name: n, ClientID: c.ID, Enabled: true, CreatedAt: now, UpdatedAt: now}
	err = a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := a.d.Agents.Create(ctx, ag); err != nil {
			return err
		}
		return writeAudit(ctx, a.d.Audit, now, ActionAgentCreate, targetAgent, ag.ID, map[string]any{"clientId": c.ID})
	}, txName("create_agent"))
	if errors.Is(err, agents.ErrNameTaken) {
		return domain.Agent{}, errAgentNameTaken()
	} else if err != nil {
		return domain.Agent{}, fmt.Errorf("create the agent: %w", err)
	}
	a.LogChange(ctx, actor, "Agents_create", ag.ID)
	return ag, nil
}

// UpdateAgent changes the name or the enabled flag of an agent. A nil field
// does not change. An empty change returns the agent.
func (a *Admin) UpdateAgent(ctx context.Context, actor, id string, name *string, enabled *bool) (domain.Agent, error) {
	ag, err := a.getAgent(ctx, id)
	if err != nil {
		return domain.Agent{}, err
	}
	if name == nil && enabled == nil {
		return ag, nil
	}
	if name != nil {
		n, err := domain.CheckAgentName(*name)
		if err != nil {
			return domain.Agent{}, errAgentName()
		}
		name = &n
	}
	var fields []string
	if name != nil && *name != ag.Name {
		fields = append(fields, "name")
	}
	if enabled != nil && *enabled != ag.Enabled {
		fields = append(fields, "enabled")
	}
	err = a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		ag, err = a.d.Agents.Patch(ctx, ag.ID, name, enabled, a.agentNow())
		if err != nil {
			return err
		}
		if len(fields) == 0 {
			// The request changed no stored value, so there is no entry.
			return nil
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionAgentUpdate, targetAgent, ag.ID, map[string]any{"fields": fields})
	}, txName("update_agent"))
	if errors.Is(err, agents.ErrNameTaken) {
		return domain.Agent{}, errAgentNameTaken()
	} else if errors.Is(err, agents.ErrNotFound) {
		return domain.Agent{}, errAgentNotFound()
	} else if err != nil {
		return domain.Agent{}, fmt.Errorf("update the agent: %w", err)
	}
	a.LogChange(ctx, actor, "Agents_update", ag.ID)
	return ag, nil
}

// ListAgentRoles returns a page of the role assignments of an agent. An agent
// has no implicit role.
func (a *Admin) ListAgentRoles(ctx context.Context, agentID string, p ListPage) (Page[domain.RoleAssignment], error) {
	n, err := p.size()
	if err != nil {
		return Page[domain.RoleAssignment]{}, err
	}
	cur, err := DecodeRoleCursor(p.Token)
	if err != nil {
		return Page[domain.RoleAssignment]{}, err
	}
	if _, err := a.getAgent(ctx, agentID); err != nil {
		return Page[domain.RoleAssignment]{}, err
	}
	items, err := a.d.AgentRoles.Page(ctx, agentID, cur, n+1)
	if err != nil {
		return Page[domain.RoleAssignment]{}, fmt.Errorf("list agent roles: %w", err)
	}
	return rolePage(items, n), nil
}

// AssignAgentRole gives a role to an agent. The role must be in a published
// manifest. The call is idempotent.
func (a *Admin) AssignAgentRole(ctx context.Context, actor, agentID string, ref domain.RoleRef) (domain.RoleAssignment, error) {
	ag, err := a.getAgent(ctx, agentID)
	if err != nil {
		return domain.RoleAssignment{}, err
	}
	if err := a.roleExists(ctx, ref); err != nil {
		return domain.RoleAssignment{}, err
	}
	err = a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		added, err := a.d.AgentRoles.Assign(ctx, ag.ID, ref, domain.AssignmentAPI)
		if err != nil {
			return err
		}
		if !added {
			// The agent had the role. Nothing changed, so there is no entry.
			return nil
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionAgentRoleAssign, targetAgent, ag.ID, map[string]any{"role": ref.String()})
	}, txName("assign_agent_role"))
	if err != nil {
		return domain.RoleAssignment{}, err
	}
	a.LogChange(ctx, actor, "AgentRoles_assign", ag.ID)
	got, ok, err := a.d.AgentRoles.Get(ctx, ag.ID, ref)
	if err != nil {
		return domain.RoleAssignment{}, err
	}
	if !ok {
		return domain.RoleAssignment{Role: ref, Source: domain.AssignmentAPI}, nil
	}
	return got, nil
}

// RemoveAgentRole removes a role of an agent. A role that the agent does not
// have is not an error. The call then writes no identity.admin.change record,
// because nothing changed.
func (a *Admin) RemoveAgentRole(ctx context.Context, actor, agentID string, ref domain.RoleRef) error {
	ag, err := a.getAgent(ctx, agentID)
	if err != nil {
		return err
	}
	deleted := false
	err = a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		deleted, err = a.d.AgentRoles.Delete(ctx, ag.ID, ref)
		if err != nil || !deleted {
			return err
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionAgentRoleRemove, targetAgent, ag.ID, map[string]any{"role": ref.String()})
	}, txName("remove_agent_role"))
	if err != nil {
		return err
	}
	if deleted {
		a.LogChange(ctx, actor, "AgentRoles_remove", ag.ID)
	}
	return nil
}
