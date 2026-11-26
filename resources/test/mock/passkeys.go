package mock

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/mfaflow"
	"github.com/techorionai/constellation-identity/internal/ports/passkeys"
	"github.com/techorionai/constellation-identity/internal/ports/webauthn"
)

// Passkeys is an in-memory repository of the passkeys.
type Passkeys struct {
	mu      sync.Mutex
	Rows    map[string]domain.PasskeyCredential
	Handles map[string][]byte
}

var _ passkeys.Repository = (*Passkeys)(nil)

// NewPasskeys makes an empty repository.
func NewPasskeys() *Passkeys {
	return &Passkeys{Rows: map[string]domain.PasskeyCredential{}, Handles: map[string][]byte{}}
}

// Add stores a credential with no checks.
func (r *Passkeys) Add(c domain.PasskeyCredential) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Rows[c.ID] = c
}

func (r *Passkeys) sorted(userID string) []domain.PasskeyCredential {
	var out []domain.PasskeyCredential
	for _, c := range r.Rows {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// List returns a page.
func (r *Passkeys) List(_ context.Context, userID string, after *domain.PageCursor, limit int) ([]domain.Passkey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.Passkey
	for _, c := range r.sorted(userID) {
		if after != nil && (c.CreatedAt.Before(after.CreatedAt) || (c.CreatedAt.Equal(after.CreatedAt) && c.ID <= after.ID)) {
			continue
		}
		out = append(out, c.Passkey)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// Get returns one passkey.
func (r *Passkeys) Get(_ context.Context, userID, id string) (domain.Passkey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.Rows[id]
	if !ok || c.UserID != userID {
		return domain.Passkey{}, passkeys.ErrNotFound
	}
	return c.Passkey, nil
}

// Credentials returns the credentials of a user.
func (r *Passkeys) Credentials(_ context.Context, userID string) ([]domain.PasskeyCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sorted(userID), nil
}

// ByCredentialID returns a credential.
func (r *Passkeys) ByCredentialID(_ context.Context, credentialID []byte) (domain.PasskeyCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.Rows {
		if bytes.Equal(c.CredentialID, credentialID) {
			return c, nil
		}
	}
	return domain.PasskeyCredential{}, passkeys.ErrNotFound
}

// Insert adds a credential.
func (r *Passkeys) Insert(_ context.Context, c domain.PasskeyCredential, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, x := range r.Rows {
		if bytes.Equal(x.CredentialID, c.CredentialID) {
			return passkeys.ErrCredentialExists
		}
		if x.UserID == c.UserID {
			n++
		}
	}
	if n >= limit {
		return passkeys.ErrLimit
	}
	r.Rows[c.ID] = c
	return nil
}

// Rename sets a name.
func (r *Passkeys) Rename(_ context.Context, userID, id, name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.Rows[id]
	if !ok || c.UserID != userID {
		return "", passkeys.ErrNotFound
	}
	old := c.Name
	c.Name = name
	r.Rows[id] = c
	return old, nil
}

// Remove deletes a passkey.
func (r *Passkeys) Remove(_ context.Context, userID, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.Rows[id]
	if !ok || c.UserID != userID {
		return passkeys.ErrNotFound
	}
	delete(r.Rows, id)
	return nil
}

// RemoveAll deletes the passkeys of a user.
func (r *Passkeys) RemoveAll(_ context.Context, userID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.Rows {
		if c.UserID == userID {
			delete(r.Rows, id)
			n++
		}
	}
	return n, nil
}

// Count returns the number of passkeys of a user.
func (r *Passkeys) Count(_ context.Context, userID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sorted(userID)), nil
}

// AdvanceSignCount applies the sign count rule.
func (r *Passkeys) AdvanceSignCount(_ context.Context, id string, next uint32, backupState bool, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.Rows[id]
	if !ok || !domain.SignCountAccepted(c.SignCount, next) {
		return false, nil
	}
	c.SignCount, c.BackupState, c.LastUsedAt = next, backupState, &now
	r.Rows[id] = c
	return true, nil
}

// EnsureUserHandle returns or stores a handle.
func (r *Passkeys) EnsureUserHandle(_ context.Context, userID string, candidate []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.Handles[userID]; ok {
		return h, nil
	}
	r.Handles[userID] = candidate
	return candidate, nil
}

// UserIDByHandle finds a user.
func (r *Passkeys) UserIDByHandle(_ context.Context, handle []byte) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, h := range r.Handles {
		if bytes.Equal(h, handle) {
			return id, nil
		}
	}
	return "", passkeys.ErrNotFound
}

// Ceremonies is an in-memory store of the state of the ceremonies.
type Ceremonies struct {
	mu   sync.Mutex
	Rows map[string]domain.Ceremony
}

var _ mfaflow.Ceremonies = (*Ceremonies)(nil)

// NewCeremonies makes an empty store.
func NewCeremonies() *Ceremonies { return &Ceremonies{Rows: map[string]domain.Ceremony{}} }

// Put stores a state.
func (c *Ceremonies) Put(_ context.Context, kind, hash string, v domain.Ceremony, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Rows[kind+":"+hash] = v
	return nil
}

// Take reads and deletes a state.
func (c *Ceremonies) Take(_ context.Context, kind, hash string) (domain.Ceremony, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.Rows[kind+":"+hash]
	if !ok {
		return domain.Ceremony{}, mfaflow.ErrNotFound
	}
	delete(c.Rows, kind+":"+hash)
	return v, nil
}

// WebAuthn is a fake of the WebAuthn port. It does no cryptography. The test
// sets the results.
type WebAuthn struct {
	// Registered is the credential that FinishRegistration returns.
	Registered webauthn.Credential
	// Asserted is the result of FinishLogin and FinishSecondFactor.
	Asserted webauthn.Asserted
	// Err is returned by each Finish method when it is set.
	Err error
}

var _ webauthn.Service = (*WebAuthn)(nil)

// BeginRegistration returns fixed options.
func (w *WebAuthn) BeginRegistration(context.Context, webauthn.User, []webauthn.Credential) (webauthn.Options, error) {
	return webauthn.Options{JSON: []byte(`{"publicKey":{}}`), State: []byte("state")}, nil
}

// FinishRegistration returns the set credential or the error.
func (w *WebAuthn) FinishRegistration(context.Context, webauthn.User, []byte, []byte) (webauthn.Registered, error) {
	if w.Err != nil {
		return webauthn.Registered{}, w.Err
	}
	return webauthn.Registered{Credential: w.Registered}, nil
}

// BeginLogin returns fixed options.
func (w *WebAuthn) BeginLogin(context.Context) (webauthn.Options, error) {
	return webauthn.Options{JSON: []byte(`{"publicKey":{}}`), State: []byte("state")}, nil
}

// ParseAssertion returns the credential ID of the set result and the handle in the body.
func (w *WebAuthn) ParseAssertion(response []byte) ([]byte, []byte, error) {
	return w.Asserted.CredentialID, response, nil
}

// FinishLogin returns the set result or the error.
func (w *WebAuthn) FinishLogin(context.Context, []byte, []byte, webauthn.User, webauthn.Credential) (webauthn.Asserted, error) {
	return w.Asserted, w.Err
}

// BeginSecondFactor returns fixed options.
func (w *WebAuthn) BeginSecondFactor(context.Context, webauthn.User, []webauthn.Credential) (webauthn.Options, error) {
	return webauthn.Options{JSON: []byte(`{"publicKey":{}}`), State: []byte("state")}, nil
}

// FinishSecondFactor returns the set result or the error.
func (w *WebAuthn) FinishSecondFactor(context.Context, webauthn.User, []webauthn.Credential, []byte, []byte) (webauthn.Asserted, error) {
	return w.Asserted, w.Err
}
