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
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// uniqueViolation is the SQLSTATE of a unique constraint error.
const uniqueViolation = "23505"

// Users is the PostgreSQL repository of the users. Each call joins the
// transaction in the context.
type Users struct {
	pool *pgxpool.Pool
}

var _ users.Repository = (*Users)(nil)

// NewUsers makes the repository.
func NewUsers(pool *pgxpool.Pool) *Users { return &Users{pool: pool} }

const userColumns = `id, email, name, status, COALESCE(password_hash, ''), created_at, updated_at`

// Create adds a user.
func (r *Users) Create(ctx context.Context, u domain.User) error {
	_, err := clientspg.Conn(ctx, r.pool).Exec(ctx, `
		INSERT INTO users (id, email, name, status, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $6)`,
		u.ID, u.Email, u.Name, string(u.Status), u.PasswordHash, u.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == "users_email_key" {
		return users.ErrEmailTaken
	}
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// GetByID returns a user.
func (r *Users) GetByID(ctx context.Context, id string) (domain.User, error) {
	return r.get(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
}

// GetByEmail returns a user.
func (r *Users) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	return r.get(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email)
}

// LockByID returns a user and locks its row.
func (r *Users) LockByID(ctx context.Context, id string) (domain.User, error) {
	return r.get(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1 FOR UPDATE`, id)
}

func (r *Users) get(ctx context.Context, query string, arg any) (domain.User, error) {
	var (
		u      domain.User
		status string
	)
	err := clientspg.Conn(ctx, r.pool).QueryRow(ctx, query, arg).
		Scan(&u.ID, &u.Email, &u.Name, &status, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, fmt.Errorf("get user: %w", users.ErrNotFound)
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("get user: %w", err)
	}
	u.Status = domain.UserStatus(status)
	return u, nil
}

// Activate sets the password hash and the status active.
func (r *Users) Activate(ctx context.Context, id, passwordHash string, now time.Time) error {
	return r.update(ctx, `UPDATE users SET password_hash = $2, status = 'active', updated_at = $3 WHERE id = $1`,
		id, passwordHash, now)
}

// SetPasswordHash replaces the password hash.
func (r *Users) SetPasswordHash(ctx context.Context, id, passwordHash string, now time.Time) error {
	return r.update(ctx, `UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1`, id, passwordHash, now)
}

// SetStatus sets the status of a user.
func (r *Users) SetStatus(ctx context.Context, id string, status domain.UserStatus, now time.Time) error {
	return r.update(ctx, `UPDATE users SET status = $2, updated_at = $3 WHERE id = $1`, id, string(status), now)
}

func (r *Users) update(ctx context.Context, query string, args ...any) error {
	tag, err := clientspg.Conn(ctx, r.pool).Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("update user: %w", users.ErrNotFound)
	}
	return nil
}
