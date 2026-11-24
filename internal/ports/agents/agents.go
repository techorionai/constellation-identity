// Package agents is the port of the agent repository.
package agents

import (
	"context"
	"errors"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Errors of the repository.
var (
	// ErrNotFound means the repository has no agent with the ID.
	ErrNotFound = errors.New("agent not found")
	// ErrNameTaken means an agent has the name.
	ErrNameTaken = errors.New("agent name taken")
)

// Repository stores the agents. A call joins the transaction in the context.
type Repository interface {
	// Create adds an agent. A used name gives ErrNameTaken.
	Create(ctx context.Context, a domain.Agent) error
	// Get returns an agent. It returns an error that wraps ErrNotFound.
	Get(ctx context.Context, id string) (domain.Agent, error)
	// Update writes the name, the enabled flag, and the update time. A used
	// name gives ErrNameTaken. A missing agent gives an error that wraps
	// ErrNotFound.
	Update(ctx context.Context, a domain.Agent) error
	// List returns up to limit agents in order of the creation time and the ID,
	// after the cursor. A nil cursor means the start.
	List(ctx context.Context, after *domain.PageCursor, limit int) ([]domain.Agent, error)
}
