package mock

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/passwordhasher"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/users"
	"github.com/techorionai/constellation-platform-go/transaction"
)

// Tx is a transactor that runs the function and makes no transaction.
type Tx struct{}

var _ transaction.Transactor = Tx{}

// WithinTx runs fn.
func (Tx) WithinTx(ctx context.Context, fn func(ctx context.Context) error, _ ...transaction.Option) error {
	return fn(ctx)
}

// AfterCommit runs fn at once.
func (Tx) AfterCommit(ctx context.Context, fn func(ctx context.Context)) { fn(ctx) }

// Users is an in-memory user repository.
type Users struct {
	mu   sync.Mutex
	Rows map[string]domain.User
}

var _ users.Repository = (*Users)(nil)

// NewUsers makes an empty repository.
func NewUsers() *Users { return &Users{Rows: map[string]domain.User{}} }

// Create adds a user.
func (r *Users) Create(_ context.Context, u domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.Rows {
		if o.Email == u.Email {
			return users.ErrEmailTaken
		}
	}
	r.Rows[u.ID] = u
	return nil
}

func (r *Users) find(match func(domain.User) bool) (domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.Rows {
		if match(u) {
			return u, nil
		}
	}
	return domain.User{}, users.ErrNotFound
}

// GetByID returns a user.
func (r *Users) GetByID(_ context.Context, id string) (domain.User, error) {
	return r.find(func(u domain.User) bool { return u.ID == id })
}

// GetByEmail returns a user.
func (r *Users) GetByEmail(_ context.Context, email string) (domain.User, error) {
	return r.find(func(u domain.User) bool { return u.Email == email })
}

// LockByID returns a user.
func (r *Users) LockByID(ctx context.Context, id string) (domain.User, error) {
	return r.GetByID(ctx, id)
}

func (r *Users) change(id string, f func(*domain.User)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.Rows[id]
	if !ok {
		return users.ErrNotFound
	}
	f(&u)
	r.Rows[id] = u
	return nil
}

// Activate sets the hash and the status active.
func (r *Users) Activate(_ context.Context, id, hash string, _ time.Time) error {
	return r.change(id, func(u *domain.User) { u.PasswordHash, u.Status = hash, domain.UserActive })
}

// SetPasswordHash sets the hash.
func (r *Users) SetPasswordHash(_ context.Context, id, hash string, _ time.Time) error {
	return r.change(id, func(u *domain.User) { u.PasswordHash = hash })
}

// SetStatus sets the status.
func (r *Users) SetStatus(_ context.Context, id string, status domain.UserStatus, _ time.Time) error {
	return r.change(id, func(u *domain.User) { u.Status = status })
}

// Sessions is an in-memory session repository.
type Sessions struct {
	mu   sync.Mutex
	Rows map[string]domain.Session
	// Touches counts the calls of Touch.
	Touches int
}

var _ sessions.Repository = (*Sessions)(nil)

// NewSessions makes an empty repository.
func NewSessions() *Sessions { return &Sessions{Rows: map[string]domain.Session{}} }

// Create adds a session.
func (r *Sessions) Create(_ context.Context, s domain.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Rows[s.ID] = s
	return nil
}

// GetByTokenHash returns a session.
func (r *Sessions) GetByTokenHash(_ context.Context, hash string) (domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.Rows {
		if s.TokenHash == hash {
			return s, nil
		}
	}
	return domain.Session{}, sessions.ErrNotFound
}

// Touch sets the times.
func (r *Sessions) Touch(_ context.Context, id string, lastSeen, idle time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.Rows[id]
	s.LastSeenAt, s.IdleExpiresAt = lastSeen, idle
	r.Rows[id] = s
	r.Touches++
	return nil
}

// RevokeByTokenHash revokes a session.
func (r *Sessions) RevokeByTokenHash(_ context.Context, hash string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.Rows {
		if s.TokenHash == hash && s.RevokedAt == nil {
			s.RevokedAt = &now
			r.Rows[id] = s
		}
	}
	return nil
}

// CountActive counts the valid sessions.
func (r *Sessions) CountActive(_ context.Context, now time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, s := range r.Rows {
		if s.Valid(now) {
			n++
		}
	}
	return n, nil
}

// OneTimeTokens is an in-memory token repository.
type OneTimeTokens struct {
	mu   sync.Mutex
	Rows map[string]domain.OneTimeToken
}

// NewOneTimeTokens makes an empty repository.
func NewOneTimeTokens() *OneTimeTokens { return &OneTimeTokens{Rows: map[string]domain.OneTimeToken{}} }

// Create adds a token.
func (r *OneTimeTokens) Create(_ context.Context, t domain.OneTimeToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Rows[t.Hash] = t
	return nil
}

// Use marks a token as used.
func (r *OneTimeTokens) Use(_ context.Context, hash string, purpose domain.TokenPurpose, now time.Time) (string, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.Rows[hash]
	if !ok || t.Purpose != purpose || t.UsedAt != nil || !t.ExpiresAt.After(now) {
		return "", false, nil
	}
	t.UsedAt = &now
	r.Rows[hash] = t
	return t.UserID, true, nil
}

// IsValid reports whether a token can be used.
func (r *OneTimeTokens) IsValid(_ context.Context, hash string, purpose domain.TokenPurpose, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.Rows[hash]
	return ok && t.Purpose == purpose && t.UsedAt == nil && t.ExpiresAt.After(now), nil
}

// FindValid reads a token that can be used.
func (r *OneTimeTokens) FindValid(_ context.Context, hash string, purpose domain.TokenPurpose, now time.Time) (string, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.Rows[hash]
	if !ok || t.Purpose != purpose || t.UsedAt != nil || !t.ExpiresAt.After(now) {
		return "", false, nil
	}
	return t.UserID, true, nil
}

// HasValidSetup reports whether a setup token can be used.
func (r *OneTimeTokens) HasValidSetup(_ context.Context, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.Rows {
		if t.Purpose == domain.PurposeSetup && t.UsedAt == nil && t.ExpiresAt.After(now) {
			return true, nil
		}
	}
	return false, nil
}

// DeleteUnusedSetup deletes the unused setup tokens.
func (r *OneTimeTokens) DeleteUnusedSetup(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for h, t := range r.Rows {
		if t.Purpose == domain.PurposeSetup && t.UsedAt == nil {
			delete(r.Rows, h)
		}
	}
	return nil
}

// DeleteUnusedInvites deletes the unused invites of a user.
func (r *OneTimeTokens) DeleteUnusedInvites(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for h, t := range r.Rows {
		if t.Purpose == domain.PurposeInvite && t.UserID == userID && t.UsedAt == nil {
			delete(r.Rows, h)
		}
	}
	return nil
}

// WithSetupLock runs fn.
func (r *OneTimeTokens) WithSetupLock(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// UserRoles is an in-memory role assignment repository.
type UserRoles struct {
	mu   sync.Mutex
	Rows map[string][]domain.RoleRef
	// Users is used to find the status of the holders.
	Users *Users
	// Perms gives the permissions of a role. A role with no entry is pending.
	Perms map[domain.RoleRef][]string
}

// NewUserRoles makes an empty repository.
func NewUserRoles(u *Users) *UserRoles {
	return &UserRoles{Rows: map[string][]domain.RoleRef{}, Users: u, Perms: map[domain.RoleRef][]string{}}
}

// Assign gives a role.
func (r *UserRoles) Assign(_ context.Context, userID string, role domain.RoleRef, _ domain.AssignmentSource) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(r.Rows[userID], role) {
		r.Rows[userID] = append(r.Rows[userID], role)
	}
	return nil
}

// Assignments returns the assignments of a user.
func (r *UserRoles) Assignments(_ context.Context, userID string) ([]domain.RoleAssignment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.RoleAssignment
	for _, ref := range r.Rows[userID] {
		out = append(out, domain.RoleAssignment{Role: ref, Source: domain.AssignmentAPI})
	}
	return out, nil
}

// ActiveUserHasRole reports whether an active user has the role.
func (r *UserRoles) ActiveUserHasRole(_ context.Context, role domain.RoleRef) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, refs := range r.Rows {
		if !slices.Contains(refs, role) {
			continue
		}
		if u, ok := r.Users.Rows[id]; ok && u.Status == domain.UserActive {
			return true, nil
		}
	}
	return false, nil
}

// Hasher is a fake password hasher. Its hash is the password with a prefix. It
// counts the calls.
type Hasher struct {
	mu sync.Mutex
	// Hashes and Verifies count the calls.
	Hashes   int
	Verifies int
	// Rehash makes Verify ask for a new hash.
	Rehash bool
	// Err is returned by Hash and Verify when it is set.
	Err error
}

var _ passwordhasher.Hasher = (*Hasher)(nil)

// Normalize returns the password.
func (h *Hasher) Normalize(p string) string { return p }

// Hash returns the fake hash.
func (h *Hasher) Hash(_ context.Context, p string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Hashes++
	if h.Err != nil {
		return "", h.Err
	}
	return "fake$" + p, nil
}

// Verify compares the fake hash.
func (h *Hasher) Verify(_ context.Context, p, encoded string) (bool, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Verifies++
	if h.Err != nil {
		return false, false, h.Err
	}
	return encoded == "fake$"+p, h.Rehash, nil
}

// Runs returns the number of hash and verify calls.
func (h *Hasher) Runs() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.Hashes + h.Verifies
}

// Limiter is an in-memory login limiter.
type Limiter struct {
	mu     sync.Mutex
	Emails map[string]int64
	IPs    map[string]int64
	// Err is returned by every call when it is set.
	Err error
	// SuccessErr is returned by RecordSuccess when it is set.
	SuccessErr error
}

// NewLimiter makes a limiter with no attempts.
func NewLimiter() *Limiter { return &Limiter{Emails: map[string]int64{}, IPs: map[string]int64{}} }

// Reserve adds an attempt and returns the new counts.
func (l *Limiter) Reserve(_ context.Context, email, ip string) (int64, int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.Err != nil {
		return 0, 0, fmt.Errorf("limiter: %w", l.Err)
	}
	l.Emails[email]++
	l.IPs[ip]++
	return l.Emails[email], l.IPs[ip], nil
}

// RecordSuccess deletes the counter of the email and decreases the counter of
// the IP, but not below 0.
func (l *Limiter) RecordSuccess(_ context.Context, email, ip string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.SuccessErr != nil {
		return fmt.Errorf("limiter: %w", l.SuccessErr)
	}
	delete(l.Emails, email)
	if l.IPs[ip] > 0 {
		l.IPs[ip]--
	}
	return nil
}
