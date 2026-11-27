package keys

import (
	"context"
	"errors"
	"fmt"

	"github.com/techorionai/constellation-platform-go/audit"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// The actions of the audit entries of the signing keys. Each entry has the
// result success and the target type signing_key. The target ID is the kid.
const (
	ActionCreate      = "identity:signing_key:create"
	ActionActivate    = "identity:signing_key:activate"
	ActionRetire      = "identity:signing_key:retire"
	ActionDelete      = "identity:signing_key:delete"
	ActionForceRotate = "identity:signing_key:force_rotate"
)

// OriginCLI is the value of details.origin of an operator command. An
// automatic key action has no origin.
const OriginCLI = "cli"

const targetSigningKey = "signing_key"

// ErrNoAudit means that the manager has no transactor or no audit writer. The
// manager then changes no key, so that no change has no entry.
var ErrNoAudit = errors.New("the key manager has no audit writer")

func (m *Manager) checkAudit() error {
	if m.tx == nil || m.audit == nil {
		return ErrNoAudit
	}
	return nil
}

// entry makes the audit entry of a key action. The details always have the kid.
func (m *Manager) entry(action, kid string, details map[string]any) audit.Entry {
	if details == nil {
		details = map[string]any{}
	}
	if _, ok := details["kid"]; !ok && action != ActionForceRotate {
		details["kid"] = kid
	}
	return audit.Entry{
		Action: action, Result: audit.Success, Time: m.now(),
		Target:  &audit.Target{Type: targetSigningKey, ID: kid},
		Details: details,
	}
}

// write writes the entries in the transaction of the context.
func (m *Manager) write(ctx context.Context, entries ...audit.Entry) error {
	if err := m.audit.Write(ctx, entries...); err != nil {
		return fmt.Errorf("write the audit entries of the signing key: %w", err)
	}
	return nil
}

func createDetails(k domain.SigningKey, origin string) map[string]any {
	d := map[string]any{"kid": k.KID, "algorithm": k.Alg, "state": string(k.State)}
	if origin != "" {
		d["origin"] = origin
	}
	return d
}
