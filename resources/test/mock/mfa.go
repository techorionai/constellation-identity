package mock

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/mfa"
	"github.com/techorionai/constellation-identity/internal/ports/mfaflow"
	"github.com/techorionai/constellation-identity/internal/ports/secretbox"
	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
)

// MFA is an in-memory repository of the TOTP factors and the recovery codes.
type MFA struct {
	mu   sync.Mutex
	TOTP map[string]domain.TOTPRecord
	// Codes has the used_at of each code. The key of the inner map is the hash.
	Codes map[string]map[string]*time.Time
}

var _ mfa.Repository = (*MFA)(nil)

// NewMFA makes an empty repository.
func NewMFA() *MFA {
	return &MFA{TOTP: map[string]domain.TOTPRecord{}, Codes: map[string]map[string]*time.Time{}}
}

// GetTOTP returns the factor.
func (r *MFA) GetTOTP(_ context.Context, userID string) (domain.TOTPRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.TOTP[userID]
	if !ok {
		return domain.TOTPRecord{}, mfa.ErrNotFound
	}
	return rec, nil
}

// EnableTOTP adds the factor and replaces the codes.
func (r *MFA) EnableTOTP(_ context.Context, rec domain.TOTPRecord, hashes [][]byte, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.TOTP[rec.UserID]; ok {
		return mfa.ErrAlreadyEnabled
	}
	r.TOTP[rec.UserID] = rec
	r.Codes[rec.UserID] = map[string]*time.Time{}
	for _, h := range hashes {
		r.Codes[rec.UserID][string(h)] = nil
	}
	return nil
}

// AdvanceStep sets the step if it is larger.
func (r *MFA) AdvanceStep(_ context.Context, userID string, step int64, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.TOTP[userID]
	if !ok || rec.LastUsedStep >= step {
		return false, nil
	}
	rec.LastUsedStep, rec.LastUsedAt = step, &now
	r.TOTP[userID] = rec
	return true, nil
}

// UseRecoveryCode uses a code.
func (r *MFA) UseRecoveryCode(_ context.Context, userID string, hash []byte, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	used, ok := r.Codes[userID][string(hash)]
	if !ok || used != nil {
		return false, nil
	}
	r.Codes[userID][string(hash)] = &now
	return true, nil
}

// ReplaceRecoveryCodes replaces the codes.
func (r *MFA) ReplaceRecoveryCodes(_ context.Context, userID string, hashes [][]byte, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Codes[userID] = map[string]*time.Time{}
	for _, h := range hashes {
		r.Codes[userID][string(h)] = nil
	}
	return nil
}

// State returns the MFA data.
func (r *MFA) State(_ context.Context, userID string) (domain.MFAState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var st domain.MFAState
	if rec, ok := r.TOTP[userID]; ok {
		st.HasTOTP, st.TOTPAt, st.LastUsedAt = true, rec.CreatedAt, rec.LastUsedAt
	}
	for _, used := range r.Codes[userID] {
		if used == nil {
			st.CodesRemaining++
		}
	}
	return st, nil
}

// RemoveAll removes the factor and the codes.
func (r *MFA) RemoveAll(_ context.Context, userID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, had := r.TOTP[userID]
	delete(r.TOTP, userID)
	delete(r.Codes, userID)
	return had, nil
}

// Pending is an in-memory store of the pending logins.
type Pending struct {
	mu       sync.Mutex
	Rows     map[string]domain.PendingLogin
	Attempts map[string]int64
	// Err is returned by every call when it is set.
	Err error
}

var _ mfaflow.PendingLogins = (*Pending)(nil)

// NewPending makes an empty store.
func NewPending() *Pending {
	return &Pending{Rows: map[string]domain.PendingLogin{}, Attempts: map[string]int64{}}
}

// Put stores a pending login.
func (p *Pending) Put(_ context.Context, hash string, v domain.PendingLogin, _ time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Err != nil {
		return p.Err
	}
	p.Rows[hash] = v
	return nil
}

// Get reads a pending login.
func (p *Pending) Get(_ context.Context, hash string) (domain.PendingLogin, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Err != nil {
		return domain.PendingLogin{}, p.Err
	}
	v, ok := p.Rows[hash]
	if !ok {
		return domain.PendingLogin{}, mfaflow.ErrNotFound
	}
	return v, nil
}

// Take reads and deletes a pending login.
func (p *Pending) Take(_ context.Context, hash string) (domain.PendingLogin, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Err != nil {
		return domain.PendingLogin{}, p.Err
	}
	v, ok := p.Rows[hash]
	if !ok {
		return domain.PendingLogin{}, mfaflow.ErrNotFound
	}
	delete(p.Rows, hash)
	return v, nil
}

// Delete removes a pending login.
func (p *Pending) Delete(_ context.Context, hash string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.Rows, hash)
	delete(p.Attempts, hash)
	return nil
}

// Attempt counts an attempt.
func (p *Pending) Attempt(_ context.Context, hash string, _ time.Duration) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Err != nil {
		return 0, p.Err
	}
	p.Attempts[hash]++
	return p.Attempts[hash], nil
}

// Setups is an in-memory store of the setup secrets.
type Setups struct {
	mu   sync.Mutex
	Rows map[string][]byte
}

var _ mfaflow.SetupSecrets = (*Setups)(nil)

// NewSetups makes an empty store.
func NewSetups() *Setups { return &Setups{Rows: map[string][]byte{}} }

// Put stores a secret.
func (s *Setups) Put(_ context.Context, key string, secret []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Rows[key] = append([]byte(nil), secret...)
	return nil
}

// Get reads a secret.
func (s *Setups) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.Rows[key]
	if !ok {
		return nil, mfaflow.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

// Delete removes a secret.
func (s *Setups) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Rows, key)
	return nil
}

// Failures is an in-memory failure counter.
type Failures struct {
	mu     sync.Mutex
	Counts map[string]int64
	// Err is returned by Reserve when it is set.
	Err error
}

var _ mfaflow.Failures = (*Failures)(nil)

// NewFailures makes an empty counter.
func NewFailures() *Failures { return &Failures{Counts: map[string]int64{}} }

// Reserve adds an attempt.
func (f *Failures) Reserve(_ context.Context, userID string, _ time.Duration) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return 0, f.Err
	}
	f.Counts[userID]++
	return f.Counts[userID], nil
}

// Release takes an attempt back.
func (f *Failures) Release(_ context.Context, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Counts[userID] > 0 {
		f.Counts[userID]--
	}
	return nil
}

// Sealer is a fake sealer. It does not encrypt. It only binds the value to the
// user, so that a test can check the binding.
type Sealer struct{}

var _ secretbox.Sealer = Sealer{}

// Seal returns the user ID, a separator, and the plain text.
func (Sealer) Seal(userID string, plain []byte) ([]byte, string, error) {
	return append([]byte(userID+"|"), plain...), "test", nil
}

// Open checks the user ID and returns the plain text.
func (Sealer) Open(userID string, sealed []byte) ([]byte, error) {
	prefix := []byte(userID + "|")
	if !bytes.HasPrefix(sealed, prefix) {
		return nil, fmt.Errorf("open: %w", secretbox.ErrCannotOpen)
	}
	return append([]byte(nil), sealed[len(prefix):]...), nil
}

// Events is a recorder of the audit entries and the notices.
type Events struct {
	mu      sync.Mutex
	Audits  []securityevents.AuditEntry
	Notices []securityevents.Notice
	// Err is returned by both methods when it is set. The call is recorded first.
	Err error
}

var _ securityevents.Events = (*Events)(nil)

// RecordAudit records an entry.
func (e *Events) RecordAudit(_ context.Context, a securityevents.AuditEntry) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Audits = append(e.Audits, a)
	return e.Err
}

// NotifyUser records a notice.
func (e *Events) NotifyUser(_ context.Context, n securityevents.Notice) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Notices = append(e.Notices, n)
	return e.Err
}
