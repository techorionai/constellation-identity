package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	clientspg "github.com/techorionai/constellation-platform-go/clients/postgres"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/agents"
)

// Agents is the PostgreSQL repository of the agents.
type Agents struct {
	pool *pgxpool.Pool
}

var _ agents.Repository = (*Agents)(nil)

// NewAgents makes the repository.
func NewAgents(pool *pgxpool.Pool) *Agents { return &Agents{pool: pool} }

const agentColumns = `id, name, client_id, enabled, created_at, updated_at`

func scanAgent(row pgx.Row) (domain.Agent, error) {
	var a domain.Agent
	err := row.Scan(&a.ID, &a.Name, &a.ClientID, &a.Enabled, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

func isNameTaken(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == "agents_name_key"
}

// Create adds an agent.
func (r *Agents) Create(ctx context.Context, a domain.Agent) error {
	_, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO agents (id, name, client_id, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, a.ID, a.Name, a.ClientID, a.Enabled, a.CreatedAt, a.UpdatedAt)
	if isNameTaken(err) {
		return agents.ErrNameTaken
	}
	if err != nil {
		return fmt.Errorf("create agent: %w", err)
	}
	return nil
}

// Get returns an agent.
func (r *Agents) Get(ctx context.Context, id string) (domain.Agent, error) {
	a, err := scanAgent(clientspg.Conn(ctx, r.pool).QueryRow(ctx, `SELECT `+agentColumns+` FROM agents WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Agent{}, fmt.Errorf("agent %s: %w", id, agents.ErrNotFound)
	}
	if err != nil {
		return domain.Agent{}, fmt.Errorf("get agent: %w", err)
	}
	return a, nil
}

// Update writes the name and the enabled flag.
func (r *Agents) Update(ctx context.Context, a domain.Agent) error {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx,
		`UPDATE agents SET name = $2, enabled = $3, updated_at = $4 WHERE id = $1`,
		a.ID, a.Name, a.Enabled, a.UpdatedAt.UTC().Truncate(time.Microsecond))
	if isNameTaken(err) {
		return agents.ErrNameTaken
	}
	if err != nil {
		return fmt.Errorf("update agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent %s: %w", a.ID, agents.ErrNotFound)
	}
	return nil
}

// List returns a page of agents.
func (r *Agents) List(ctx context.Context, after *domain.PageCursor, limit int) ([]domain.Agent, error) {
	query := `SELECT ` + agentColumns + ` FROM agents`
	var args []any
	if after != nil {
		query += ` WHERE (created_at, id) > ($1, $2)`
		args = append(args, after.CreatedAt, after.ID)
	}
	query += ` ORDER BY created_at, id LIMIT ` + fmt.Sprint(limit)
	rows, err := clientspg.Conn(ctx, r.pool).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()
	var out []domain.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	return out, nil
}
