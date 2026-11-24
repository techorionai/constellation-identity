package httpapi

import (
	"context"

	"github.com/google/uuid"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

func genAgentValue(a domain.Agent) gen.Agent {
	id, _ := uuid.Parse(a.ID)
	return gen.Agent{
		ClientId: a.ClientID, CreatedAt: a.CreatedAt, Enabled: a.Enabled, Id: id, Name: a.Name, UpdatedAt: a.UpdatedAt,
	}
}

// AgentsList lists the agents.
func (s *Server) AgentsList(ctx context.Context, r gen.AgentsListRequestObject) (gen.AgentsListResponseObject, error) {
	p, err := s.d.Admin.ListAgents(ctx, listPage(r.Params.PageSize, r.Params.PageToken))
	if err != nil {
		return nil, err
	}
	items := make([]gen.Agent, 0, len(p.Items))
	for _, a := range p.Items {
		items = append(items, genAgentValue(a))
	}
	return gen.AgentsList200JSONResponse{Items: items, NextPageToken: nextToken(p.Next)}, nil
}

// AgentsCreate makes an agent.
func (s *Server) AgentsCreate(ctx context.Context, r gen.AgentsCreateRequestObject) (gen.AgentsCreateResponseObject, error) {
	if r.Body == nil {
		return nil, apperrors.NewInvalidInput("the body is required")
	}
	a, err := s.d.Admin.CreateAgent(ctx, actorID(ctx), r.Body.Name, r.Body.ClientId)
	if err != nil {
		return nil, err
	}
	return gen.AgentsCreate201JSONResponse(genAgentValue(a)), nil
}

// AgentsGet returns an agent.
func (s *Server) AgentsGet(ctx context.Context, r gen.AgentsGetRequestObject) (gen.AgentsGetResponseObject, error) {
	a, err := s.d.Admin.GetAgent(ctx, r.AgentId)
	if err != nil {
		return nil, err
	}
	return gen.AgentsGet200JSONResponse(genAgentValue(a)), nil
}

// AgentsUpdate changes the name or the state of an agent.
func (s *Server) AgentsUpdate(ctx context.Context, r gen.AgentsUpdateRequestObject) (gen.AgentsUpdateResponseObject, error) {
	if r.Body == nil {
		return nil, apperrors.NewInvalidInput("the body is required")
	}
	a, err := s.d.Admin.UpdateAgent(ctx, actorID(ctx), r.AgentId, r.Body.Name, r.Body.Enabled)
	if err != nil {
		return nil, err
	}
	return gen.AgentsUpdate200JSONResponse(genAgentValue(a)), nil
}

// AgentRolesList lists the role assignments of an agent.
func (s *Server) AgentRolesList(ctx context.Context, r gen.AgentRolesListRequestObject) (gen.AgentRolesListResponseObject, error) {
	p, err := s.d.Admin.ListAgentRoles(ctx, r.AgentId, listPage(r.Params.PageSize, r.Params.PageToken))
	if err != nil {
		return nil, err
	}
	return gen.AgentRolesList200JSONResponse{Items: genAssignments(p.Items), NextPageToken: nextToken(p.Next)}, nil
}

// AgentRolesAssign gives a role to an agent.
func (s *Server) AgentRolesAssign(ctx context.Context, r gen.AgentRolesAssignRequestObject) (gen.AgentRolesAssignResponseObject, error) {
	ref, err := parseRole(r.Role)
	if err != nil {
		return nil, err
	}
	a, err := s.d.Admin.AssignAgentRole(ctx, actorID(ctx), r.AgentId, ref)
	if err != nil {
		return nil, err
	}
	return gen.AgentRolesAssign200JSONResponse(genAssignment(a)), nil
}

// AgentRolesRemove removes a role from an agent.
func (s *Server) AgentRolesRemove(ctx context.Context, r gen.AgentRolesRemoveRequestObject) (gen.AgentRolesRemoveResponseObject, error) {
	ref, err := parseRole(r.Role)
	if err != nil {
		return nil, err
	}
	if err := s.d.Admin.RemoveAgentRole(ctx, actorID(ctx), r.AgentId, ref); err != nil {
		return nil, err
	}
	return gen.AgentRolesRemove204Response{}, nil
}
