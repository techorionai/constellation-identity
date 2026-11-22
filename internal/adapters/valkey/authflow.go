package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/authflow"
)

// Store keeps the short-lived records of the code flow in Valkey. It uses
// SET, GET, and GETDEL only, because the ACL of the service denies scripts.
// Each call has a time limit. A timeout or a connection error is an error, and
// it is not "not found".
type Store struct {
	client valkeygo.Client
	keys   KeyMaker
}

var _ authflow.AuthRequests = (*Store)(nil)

// NewStore makes the store.
func NewStore(client valkeygo.Client, keys KeyMaker) *Store {
	return &Store{client: client, keys: keys}
}

func (s *Store) put(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode record: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	secs := max(int64(ttl/time.Second), 1)
	if err := s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(b)).ExSeconds(secs).Build()).Error(); err != nil {
		return fmt.Errorf("store record: %w", err)
	}
	return nil
}

func (s *Store) read(ctx context.Context, key string, del bool, out any) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	cmd := s.client.B().Get().Key(key).Build()
	if del {
		cmd = s.client.B().Getdel().Key(key).Build()
	}
	v, err := s.client.Do(ctx, cmd).ToString()
	if valkeygo.IsValkeyNil(err) {
		return authflow.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read record: %w", err)
	}
	if err := json.Unmarshal([]byte(v), out); err != nil {
		return fmt.Errorf("decode record: %w", err)
	}
	return nil
}

func (s *Store) reqKey(id string) string { return s.keys.Key("authreq", id) }
func (s *Store) codeKey(h string) string { return s.keys.Key("code", h) }
func (s *Store) usedKey(h string) string { return s.keys.Key("code-used", h) }

func wrapNotFound(err error) error {
	if errors.Is(err, authflow.ErrNotFound) {
		return fmt.Errorf("not found: %w", authflow.ErrNotFound)
	}
	return err
}

// Put stores an auth request.
func (s *Store) Put(ctx context.Context, id string, r domain.AuthRequest, ttl time.Duration) error {
	return s.put(ctx, s.reqKey(id), r, ttl)
}

// Get reads an auth request.
func (s *Store) Get(ctx context.Context, id string) (domain.AuthRequest, error) {
	var r domain.AuthRequest
	err := s.read(ctx, s.reqKey(id), false, &r)
	return r, wrapNotFound(err)
}

// Take reads and deletes an auth request.
func (s *Store) Take(ctx context.Context, id string) (domain.AuthRequest, error) {
	var r domain.AuthRequest
	err := s.read(ctx, s.reqKey(id), true, &r)
	return r, wrapNotFound(err)
}

// CodeStore is the adapter of the port authflow.Codes.
type CodeStore struct{ s *Store }

var _ authflow.Codes = CodeStore{}

// Codes returns the adapter of the code store.
func (s *Store) Codes() CodeStore { return CodeStore{s: s} }

// Put stores a code record.
func (c CodeStore) Put(ctx context.Context, hash string, rec domain.AuthCode, ttl time.Duration) error {
	return c.s.put(ctx, c.s.codeKey(hash), rec, ttl)
}

// Peek reads a code record and keeps it.
func (c CodeStore) Peek(ctx context.Context, hash string) (domain.AuthCode, error) {
	var rec domain.AuthCode
	err := c.s.read(ctx, c.s.codeKey(hash), false, &rec)
	return rec, wrapNotFound(err)
}

// Claim reads and deletes a code record in one step.
func (c CodeStore) Claim(ctx context.Context, hash string) (domain.AuthCode, error) {
	var rec domain.AuthCode
	err := c.s.read(ctx, c.s.codeKey(hash), true, &rec)
	return rec, wrapNotFound(err)
}

// MarkUsed stores the used-code marker.
func (c CodeStore) MarkUsed(ctx context.Context, hash string, m domain.UsedCode, ttl time.Duration) error {
	return c.s.put(ctx, c.s.usedKey(hash), m, ttl)
}

// GetUsed reads the used-code marker.
func (c CodeStore) GetUsed(ctx context.Context, hash string) (domain.UsedCode, error) {
	var m domain.UsedCode
	err := c.s.read(ctx, c.s.usedKey(hash), false, &m)
	return m, wrapNotFound(err)
}
