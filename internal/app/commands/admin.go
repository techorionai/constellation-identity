package commands

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/techorionai/constellation-platform-go/audit"
	"github.com/techorionai/constellation-platform-go/transaction"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/adminlock"
	"github.com/techorionai/constellation-identity/internal/ports/agentroles"
	"github.com/techorionai/constellation-identity/internal/ports/agents"
	"github.com/techorionai/constellation-identity/internal/ports/apitokens"
	"github.com/techorionai/constellation-identity/internal/ports/clientroles"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
	"github.com/techorionai/constellation-identity/internal/ports/identitylinks"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
	"github.com/techorionai/constellation-identity/internal/ports/mfa"
	"github.com/techorionai/constellation-identity/internal/ports/onetimetokens"
	"github.com/techorionai/constellation-identity/internal/ports/refreshtokens"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/userroles"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// AdminDeps are the ports of the admin use cases.
type AdminDeps struct {
	Users       users.Repository
	UserRoles   userroles.Repository
	Sessions    sessions.Repository
	Clients     clients.Repository
	ClientRoles clientroles.Repository
	Agents      agents.Repository
	AgentRoles  agentroles.Repository
	Manifests   manifests.Repository
	Tokens      onetimetokens.Repository
	Refresh     refreshtokens.Repository
	APITokens   apitokens.Repository
	Lock        adminlock.Locker
	Tx          transaction.Transactor
	// Audit writes the audit entries in the transaction of the change.
	Audit audit.Writer
	Log   *slog.Logger
	// MFA, Links, PasskeysOn, and ProviderOn give the login methods of a user for
	// the enable rule. A nil repository means that the user has none of that kind.
	MFA        mfa.Repository
	Links      identitylinks.Repository
	PasskeysOn bool
	ProviderOn domain.ProviderOn
	// Now is the clock. The default is time.Now.
	Now Clock
}

// Admin has the use cases of the admin API for users, role assignments,
// sessions, and clients. Each change writes one info log record with the
// actor, the operation, and the target. The record has no secret value.
type Admin struct{ d AdminDeps }

// NewAdmin makes the use cases.
func NewAdmin(d AdminDeps) *Admin {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Admin{d: d}
}

func (a *Admin) now() time.Time { return a.d.Now().UTC() }

// LogChange writes the info log record of an admin change. attrs are more
// key and value pairs for the record. They have no secret value.
func (a *Admin) LogChange(ctx context.Context, actor, op, target string, attrs ...any) {
	a.d.Log.InfoContext(ctx, "identity.admin.change", append([]any{"event", "identity.admin.change",
		"actor_id", actor, "operation", op, "target_id", target}, attrs...)...)
}

// Problems of the admin API.
func errLastAdmin() error {
	return apperrors.NewConflictCode("last_admin", "The change would leave no active user with the permission identity:admin.")
}

func errManagedByConfig() error {
	return apperrors.NewConflictCode("client_managed_by_config", "The clients file manages this client.")
}

func errTypeUnsupported() error {
	return apperrors.NewUnprocessable("client_type_unsupported", "The operation is not available for this type of client.")
}

func errRoleUnknown() error {
	return apperrors.NewUnprocessable("role_unknown", "The role is not in a published manifest.")
}

// --- pages ---

const (
	defaultListSize = 50
	maxListSize     = 200
	maxCursorLength = 1024
	timeLayout      = "2006-01-02T15:04:05.000000Z"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ListPage is the paging input of a list.
type ListPage struct {
	// Size is the pageSize query value. Nil means the default.
	Size  *int32
	Token string
}

// Page is a page of a list.
type Page[T any] struct {
	Items []T
	// Next is the token of the next page. It is empty on the last page.
	Next string
}

func (p ListPage) size() (int, error) {
	if p.Size == nil {
		return defaultListSize, nil
	}
	if *p.Size < 1 || *p.Size > maxListSize {
		return 0, apperrors.NewInvalidInput("pageSize must be from 1 to 200")
	}
	return int(*p.Size), nil
}

func badToken() error { return apperrors.NewInvalidInput("pageToken is not valid") }

// decodeCursor reads a token that is a base64url JSON array of two strings.
func decodeCursor(token string) (a, b string, ok bool, err error) {
	if token == "" {
		return "", "", false, nil
	}
	if len(token) > maxCursorLength {
		return "", "", false, badToken()
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", "", false, badToken()
	}
	var parts []string
	if err := json.Unmarshal(raw, &parts); err != nil || len(parts) != 2 {
		return "", "", false, badToken()
	}
	return parts[0], parts[1], true, nil
}

func encodeCursor(a, b string) string {
	raw, _ := json.Marshal([]string{a, b})
	return base64.RawURLEncoding.EncodeToString(raw)
}

// EncodeTimeCursor makes the token of a list in order of creation time and ID.
// The time has 6 digits of fraction and is in UTC.
func EncodeTimeCursor(t time.Time, id string) string {
	return encodeCursor(t.UTC().Format(timeLayout), id)
}

// DecodeTimeCursor reads a token of EncodeTimeCursor. A value that has another
// form is an invalid input.
func DecodeTimeCursor(token string) (*domain.PageCursor, error) {
	a, id, ok, err := decodeCursor(token)
	if err != nil || !ok {
		return nil, err
	}
	t, err := time.Parse(timeLayout, a)
	if err != nil || t.Format(timeLayout) != a || id == "" || len(id) > 128 {
		return nil, badToken()
	}
	return &domain.PageCursor{CreatedAt: t, ID: id}, nil
}

// EncodeRoleCursor makes the token of a role list.
func EncodeRoleCursor(r domain.RoleRef) string { return encodeCursor(r.App, r.Role) }

// DecodeRoleCursor reads a token of EncodeRoleCursor.
func DecodeRoleCursor(token string) (*domain.RoleRef, error) {
	app, role, ok, err := decodeCursor(token)
	if err != nil || !ok {
		return nil, err
	}
	if !domain.ValidAppKey(app) || !domain.ValidRoleKey(role) {
		return nil, badToken()
	}
	return &domain.RoleRef{App: app, Role: role}, nil
}

// decodeUUIDCursor is the cursor of a list whose IDs are UUIDs.
func decodeUUIDCursor(token string) (*domain.PageCursor, error) {
	c, err := DecodeTimeCursor(token)
	if err != nil || c == nil {
		return c, err
	}
	if !uuidPattern.MatchString(c.ID) {
		return nil, badToken()
	}
	return c, nil
}

// --- users ---

// ListUsers returns a page of users.
func (a *Admin) ListUsers(ctx context.Context, p ListPage) (Page[domain.User], error) {
	n, err := p.size()
	if err != nil {
		return Page[domain.User]{}, err
	}
	cur, err := decodeUUIDCursor(p.Token)
	if err != nil {
		return Page[domain.User]{}, err
	}
	items, err := a.d.Users.List(ctx, cur, n+1)
	if err != nil {
		return Page[domain.User]{}, fmt.Errorf("list users: %w", err)
	}
	out := Page[domain.User]{Items: items}
	if len(items) > n {
		out.Items = items[:n]
		last := out.Items[n-1]
		out.Next = EncodeTimeCursor(last.CreatedAt, last.ID)
	}
	return out, nil
}

// GetUser returns a user.
func (a *Admin) GetUser(ctx context.Context, id string) (domain.User, error) {
	u, err := a.d.Users.GetByID(ctx, id)
	if errors.Is(err, users.ErrNotFound) {
		return domain.User{}, apperrors.NewNotFound("the user does not exist")
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("get the user: %w", err)
	}
	return u, nil
}

// UpdateUser changes the name or the disabled state of a user. A change of the
// state of the last admin gives last_admin. The check and the change run in
// one transaction under the lock of the admin changes.
func (a *Admin) UpdateUser(ctx context.Context, actor, id string, name *string, disabled *bool) (domain.User, error) {
	var newName string
	revokedTokens := -1
	var changed []string
	if name != nil {
		n, err := domain.CheckName(*name)
		if err != nil {
			return domain.User{}, apperrors.NewInvalidInput("the name is not valid")
		}
		newName = n
	}
	err := a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := a.d.Lock.Lock(ctx); err != nil {
			return err
		}
		u, err := a.d.Users.LockByID(ctx, id)
		if errors.Is(err, users.ErrNotFound) {
			return apperrors.NewNotFound("the user does not exist")
		}
		if err != nil {
			return err
		}
		now := a.now()
		if name != nil && newName != u.Name {
			if err := a.d.Users.SetName(ctx, id, newName, now); err != nil {
				return err
			}
			changed = append(changed, "name")
		}
		switch {
		case disabled != nil && *disabled && u.Status != domain.UserDisabled:
			holder, err := a.holdsAdmin(ctx, u)
			if err != nil {
				return err
			}
			if err := a.d.Users.SetStatus(ctx, id, domain.UserDisabled, now); err != nil {
				return err
			}
			changed = append(changed, "disabled")
			if _, err := a.d.Sessions.RevokeAllOfUser(ctx, id, now); err != nil {
				return err
			}
			n, err := a.d.APITokens.RevokeAllOfUser(ctx, id, now)
			if err != nil {
				return err
			}
			revokedTokens = n
			if err := a.d.Tokens.DeleteUnusedInvites(ctx, id); err != nil {
				return err
			}
			if holder {
				if err := a.checkAdminLeft(ctx); err != nil {
					return err
				}
			}
		case disabled != nil && !*disabled && u.Status == domain.UserDisabled:
			status, err := a.enableStatus(ctx, u)
			if err != nil {
				return err
			}
			if err := a.d.Users.SetStatus(ctx, id, status, now); err != nil {
				return err
			}
			changed = append(changed, "disabled")
		}
		if len(changed) == 0 {
			return nil
		}
		return writeAudit(ctx, a.d.Audit, now, ActionUserUpdate, targetUser, id, map[string]any{"fields": changed})
	}, txName("update_user"))
	if err != nil {
		return domain.User{}, err
	}
	if revokedTokens >= 0 {
		a.LogChange(ctx, actor, "Users_update", id, "api_tokens_revoked", revokedTokens)
	} else {
		a.LogChange(ctx, actor, "Users_update", id)
	}
	return a.GetUser(ctx, id)
}

// enableStatus gives the status of a disabled user that an admin enables: active
// if the user has a login method (see domain.HasLoginMethod), else invited.
func (a *Admin) enableStatus(ctx context.Context, u domain.User) (domain.UserStatus, error) {
	passkeys := 0
	if a.d.MFA != nil {
		st, err := a.d.MFA.State(ctx, u.ID)
		if err != nil {
			return "", err
		}
		passkeys = st.Passkeys
	}
	ms, err := readMethodsState(ctx, a.d.Links, a.d.ProviderOn, a.d.PasskeysOn, u, passkeys)
	if err != nil {
		return "", err
	}
	return domain.EnableStatus(ms), nil
}

// holdsAdmin reports whether the user is active and has the permission
// identity:admin through a role that is not pending.
func (a *Admin) holdsAdmin(ctx context.Context, u domain.User) (bool, error) {
	if u.Status != domain.UserActive {
		return false, nil
	}
	perms, err := a.d.UserRoles.GrantedPermissions(ctx, u.ID)
	if err != nil {
		return false, err
	}
	return slices.Contains(perms, domain.AdminPermission), nil
}

// checkAdminLeft returns last_admin if no active user has identity:admin after
// the change. The caller holds the admin lock, so the count is exact. The
// error rolls back the transaction.
func (a *Admin) checkAdminLeft(ctx context.Context) error {
	n, err := a.d.UserRoles.CountActiveHolders(ctx, domain.AdminPermission)
	if err != nil {
		return err
	}
	if n == 0 {
		return errLastAdmin()
	}
	return nil
}

// --- user roles ---

func (a *Admin) requireUser(ctx context.Context, id string) (domain.User, error) {
	return a.GetUser(ctx, id)
}

// ListUserRoles returns a page of the role assignments of a user.
func (a *Admin) ListUserRoles(ctx context.Context, userID string, p ListPage) (Page[domain.RoleAssignment], error) {
	n, err := p.size()
	if err != nil {
		return Page[domain.RoleAssignment]{}, err
	}
	cur, err := DecodeRoleCursor(p.Token)
	if err != nil {
		return Page[domain.RoleAssignment]{}, err
	}
	if _, err := a.requireUser(ctx, userID); err != nil {
		return Page[domain.RoleAssignment]{}, err
	}
	all, err := a.d.UserRoles.Assignments(ctx, userID)
	if err != nil {
		return Page[domain.RoleAssignment]{}, fmt.Errorf("list user roles: %w", err)
	}
	return implicitRolePage(all, domain.UserRole, cur, n), nil
}

// implicitRolePage makes a page of the assignments with one implicit role. The
// implicit role shows one time, with the source config, also if a row with the
// same role exists. The list is in order of app and role.
func implicitRolePage(all []domain.RoleAssignment, implicit domain.RoleRef, cur *domain.RoleRef, n int) Page[domain.RoleAssignment] {
	all = slices.DeleteFunc(slices.Clone(all), func(x domain.RoleAssignment) bool { return x.Role == implicit })
	all = append(all, domain.RoleAssignment{Role: implicit, Source: domain.AssignmentConfig})
	sort.Slice(all, func(i, j int) bool {
		if all[i].Role.App != all[j].Role.App {
			return all[i].Role.App < all[j].Role.App
		}
		return all[i].Role.Role < all[j].Role.Role
	})
	var rest []domain.RoleAssignment
	for _, x := range all {
		if cur == nil || x.Role.App > cur.App || x.Role.App == cur.App && x.Role.Role > cur.Role {
			rest = append(rest, x)
		}
	}
	if len(rest) > n+1 {
		rest = rest[:n+1]
	}
	return rolePage(rest, n)
}

func rolePage(items []domain.RoleAssignment, n int) Page[domain.RoleAssignment] {
	out := Page[domain.RoleAssignment]{Items: items}
	if len(items) > n {
		out.Items = items[:n]
		out.Next = EncodeRoleCursor(out.Items[n-1].Role)
	}
	return out
}

func (a *Admin) roleExists(ctx context.Context, ref domain.RoleRef) error {
	_, err := a.d.Manifests.Role(ctx, ref)
	if errors.Is(err, manifests.ErrNotFound) {
		return errRoleUnknown()
	}
	if err != nil {
		return fmt.Errorf("get the role: %w", err)
	}
	return nil
}

// AssignUserRole gives a role to a user. The role must be in a published
// manifest. A holder of identity:role:assign can assign every role. In slice 1
// this permission is equal to full admin access.
func (a *Admin) AssignUserRole(ctx context.Context, actor, userID string, ref domain.RoleRef) (domain.RoleAssignment, error) {
	if _, err := a.requireUser(ctx, userID); err != nil {
		return domain.RoleAssignment{}, err
	}
	if ref == domain.UserRole {
		// Each active user has this role. It has no row, so the call writes nothing.
		return domain.RoleAssignment{Role: ref, Source: domain.AssignmentConfig}, nil
	}
	if err := a.roleExists(ctx, ref); err != nil {
		return domain.RoleAssignment{}, err
	}
	err := a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := a.d.UserRoles.Assign(ctx, userID, ref, domain.AssignmentAPI); err != nil {
			return err
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionUserRoleAssign, targetUser, userID, map[string]any{"role": ref.String()})
	}, txName("assign_user_role"))
	if err != nil {
		return domain.RoleAssignment{}, err
	}
	a.LogChange(ctx, actor, "UserRoles_assign", userID)
	all, err := a.d.UserRoles.Assignments(ctx, userID)
	if err != nil {
		return domain.RoleAssignment{}, err
	}
	for _, x := range all {
		if x.Role == ref {
			return x, nil
		}
	}
	return domain.RoleAssignment{Role: ref, Source: domain.AssignmentAPI}, nil
}

// RemoveUserRole removes a role from a user. The last active admin cannot
// lose identity:admin.
func (a *Admin) RemoveUserRole(ctx context.Context, actor, userID string, ref domain.RoleRef) error {
	if ref == domain.UserRole {
		// The implicit role cannot go. The call changes nothing.
		_, err := a.requireUser(ctx, userID)
		return err
	}
	err := a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := a.d.Lock.Lock(ctx); err != nil {
			return err
		}
		u, err := a.d.Users.LockByID(ctx, userID)
		if errors.Is(err, users.ErrNotFound) {
			return apperrors.NewNotFound("the user does not exist")
		}
		if err != nil {
			return err
		}
		holder, err := a.holdsAdmin(ctx, u)
		if err != nil {
			return err
		}
		deleted, err := a.d.UserRoles.Delete(ctx, userID, ref)
		if err != nil {
			return err
		}
		if !deleted {
			return apperrors.NewNotFound("the user does not have the role")
		}
		if holder {
			if err := a.checkAdminLeft(ctx); err != nil {
				return err
			}
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionUserRoleRemove, targetUser, userID, map[string]any{"role": ref.String()})
	}, txName("remove_user_role"))
	if err != nil {
		return err
	}
	a.LogChange(ctx, actor, "UserRoles_remove", userID)
	return nil
}

// --- sessions ---

// ListSessions returns a page of the sessions of a user that are valid now.
func (a *Admin) ListSessions(ctx context.Context, userID string, p ListPage) (Page[domain.Session], error) {
	n, err := p.size()
	if err != nil {
		return Page[domain.Session]{}, err
	}
	cur, err := decodeUUIDCursor(p.Token)
	if err != nil {
		return Page[domain.Session]{}, err
	}
	if _, err := a.requireUser(ctx, userID); err != nil {
		return Page[domain.Session]{}, err
	}
	items, err := a.d.Sessions.ListByUser(ctx, userID, a.now(), cur, n+1)
	if err != nil {
		return Page[domain.Session]{}, fmt.Errorf("list sessions: %w", err)
	}
	out := Page[domain.Session]{Items: items}
	if len(items) > n {
		out.Items = items[:n]
		last := out.Items[n-1]
		out.Next = EncodeTimeCursor(last.CreatedAt, last.ID)
	}
	return out, nil
}

// RevokeSession revokes a session and its refresh token families.
func (a *Admin) RevokeSession(ctx context.Context, actor, sessionID string) error {
	if !uuidPattern.MatchString(sessionID) {
		return apperrors.NewNotFound("the session does not exist")
	}
	err := a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		found, err := a.d.Sessions.RevokeCascade(ctx, sessionID, a.now())
		if err != nil {
			return fmt.Errorf("revoke the session: %w", err)
		}
		if !found {
			return apperrors.NewNotFound("the session does not exist")
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionSessionRevoke, targetSession, sessionID, nil)
	}, txName("revoke_session"))
	if err != nil {
		return err
	}
	a.LogChange(ctx, actor, "Sessions_revoke", sessionID)
	return nil
}

// RevokeUserSessions revokes all sessions of a user and their families.
func (a *Admin) RevokeUserSessions(ctx context.Context, actor, userID string) error {
	if _, err := a.requireUser(ctx, userID); err != nil {
		return err
	}
	err := a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		n, err := a.d.Sessions.RevokeAllOfUser(ctx, userID, a.now())
		if err != nil {
			return fmt.Errorf("revoke the sessions: %w", err)
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionSessionRevokeAll, targetUser, userID, map[string]any{"sessions": n})
	}, txName("revoke_user_sessions"))
	if err != nil {
		return err
	}
	a.LogChange(ctx, actor, "Sessions_revokeAll", userID)
	return nil
}

// --- clients ---

// ClientView is a client with its keys.
type ClientView struct {
	Client domain.Client
	Keys   []domain.ClientKey
}

// JWKInput is a key that the API gives. Extra holds the names of the members
// that a public EC key does not have.
type JWKInput struct {
	Key   domain.PublicJWK
	Extra []string
}

func invalidJWK(msg string) error { return apperrors.NewUnprocessable("invalid_jwk", msg) }

// checkJWK checks a key of a service client: a public EC P-256 key with a kid
// and no private member.
func checkJWK(in JWKInput) (domain.ClientKey, error) {
	if len(in.Extra) > 0 {
		name := in.Extra[0]
		if domain.IsPrivateJWKField(name) {
			return domain.ClientKey{}, invalidJWK("the key must not have the private member " + name)
		}
		return domain.ClientKey{}, invalidJWK("the key has the member " + name + ", which an EC key does not have")
	}
	k := in.Key
	if k.Kid == "" || len(k.Kid) > 128 {
		return domain.ClientKey{}, invalidJWK("the kid is required")
	}
	if k.Alg != "" && k.Alg != domain.AlgES256 {
		return domain.ClientKey{}, invalidJWK("the alg must be ES256")
	}
	if k.Use != "" && k.Use != "sig" {
		return domain.ClientKey{}, invalidJWK("the use must be sig")
	}
	if err := domain.ValidatePublicJWK(k); err != nil {
		return domain.ClientKey{}, invalidJWK(err.Error())
	}
	return domain.ClientKey{KID: k.Kid, PublicJWK: k}, nil
}

// ListClients returns a page of clients.
func (a *Admin) ListClients(ctx context.Context, p ListPage) (Page[ClientView], error) {
	n, err := p.size()
	if err != nil {
		return Page[ClientView]{}, err
	}
	cur, err := DecodeTimeCursor(p.Token)
	if err != nil {
		return Page[ClientView]{}, err
	}
	items, err := a.d.Clients.List(ctx, cur, n+1)
	if err != nil {
		return Page[ClientView]{}, fmt.Errorf("list clients: %w", err)
	}
	out := Page[ClientView]{}
	if len(items) > n {
		items = items[:n]
		last := items[n-1]
		out.Next = EncodeTimeCursor(last.CreatedAt, last.ID)
	}
	for _, c := range items {
		v, err := a.view(ctx, c)
		if err != nil {
			return Page[ClientView]{}, err
		}
		out.Items = append(out.Items, v)
	}
	return out, nil
}

func (a *Admin) view(ctx context.Context, c domain.Client) (ClientView, error) {
	v := ClientView{Client: c}
	if c.Type == domain.ClientTypeService {
		keys, err := a.d.Clients.Keys(ctx, c.ID)
		if err != nil {
			return ClientView{}, fmt.Errorf("get the keys: %w", err)
		}
		v.Keys = keys
	}
	return v, nil
}

func (a *Admin) getClient(ctx context.Context, id string) (domain.Client, error) {
	c, err := a.d.Clients.Get(ctx, id)
	if errors.Is(err, clients.ErrNotFound) {
		return domain.Client{}, apperrors.NewNotFound("the client does not exist")
	}
	if err != nil {
		return domain.Client{}, fmt.Errorf("get the client: %w", err)
	}
	return c, nil
}

// GetClient returns a client with its keys.
func (a *Admin) GetClient(ctx context.Context, id string) (ClientView, error) {
	c, err := a.getClient(ctx, id)
	if err != nil {
		return ClientView{}, err
	}
	return a.view(ctx, c)
}

// CreateClientInput is the input of the client creation.
type CreateClientInput struct {
	Type                   domain.ClientType
	App                    string
	Name                   string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	JWK                    *JWKInput
}

func checkClientName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" || len(n) > 200 {
		return "", apperrors.NewInvalidInput("the name must have 1 to 200 characters")
	}
	return n, nil
}

func validationErr(fields []domain.FieldError) error {
	if len(fields) == 0 {
		return nil
	}
	return apperrors.NewValidationError(fields)
}

func newClientID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random bytes: %w", err)
	}
	return "cl_" + hex.EncodeToString(b), nil
}

// CreateClient makes a client with the source api.
func (a *Admin) CreateClient(ctx context.Context, actor string, in CreateClientInput) (ClientView, error) {
	name, err := checkClientName(in.Name)
	if err != nil {
		return ClientView{}, err
	}
	if in.Type != domain.ClientTypePublic && in.Type != domain.ClientTypeService {
		return ClientView{}, apperrors.NewInvalidInput("the type must be public or service")
	}
	if !domain.ValidAppKey(in.App) {
		return ClientView{}, apperrors.NewUnprocessable("invalid_app", "the app is not an app key")
	}
	var key *domain.ClientKey
	switch in.Type {
	case domain.ClientTypeService:
		if in.App == domain.IdentityApp {
			return ClientView{}, apperrors.NewUnprocessable("app_reserved", "a service client cannot use the app identity")
		}
		if len(in.RedirectURIs) > 0 || len(in.PostLogoutRedirectURIs) > 0 {
			return ClientView{}, errTypeUnsupported()
		}
		if in.JWK != nil {
			k, err := checkJWK(*in.JWK)
			if err != nil {
				return ClientView{}, err
			}
			key = &k
		}
	default:
		if in.JWK != nil {
			return ClientView{}, errTypeUnsupported()
		}
		fields := domain.CheckRedirectURIs("redirectUris", in.RedirectURIs)
		if len(in.RedirectURIs) == 0 {
			fields = append(fields, domain.FieldError{Code: "invalid_redirect_uri", Field: "redirectUris", Message: "a public client needs a redirect URI"})
		}
		fields = append(fields, domain.CheckRedirectURIs("postLogoutRedirectUris", in.PostLogoutRedirectURIs)...)
		if err := validationErr(fields); err != nil {
			return ClientView{}, err
		}
	}
	id, err := newClientID()
	if err != nil {
		return ClientView{}, err
	}
	now := a.now()
	c := domain.Client{
		ID: id, Type: in.Type, App: in.App, Name: name, Source: domain.SourceAPI, CreatedAt: now, UpdatedAt: now,
		RedirectURIs: in.RedirectURIs, PostLogoutRedirectURIs: in.PostLogoutRedirectURIs,
	}
	if key != nil {
		key.ClientID, key.CreatedAt = id, now
	}
	err = a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := a.d.Clients.Create(ctx, c, key); err != nil {
			return fmt.Errorf("create the client: %w", err)
		}
		return writeAudit(ctx, a.d.Audit, now, ActionClientCreate, targetClient, id, map[string]any{"type": string(in.Type), "app": in.App})
	}, txName("create_client"))
	if err != nil {
		return ClientView{}, err
	}
	a.LogChange(ctx, actor, "Clients_create", id)
	return a.GetClient(ctx, id)
}

// UpdateClientInput is the input of the client change. A nil field does not
// change.
type UpdateClientInput struct {
	Type                   *domain.ClientType
	Name                   *string
	RedirectURIs           *[]string
	PostLogoutRedirectURIs *[]string
	Disabled               *bool
}

// UpdateClient changes a client of the source api. A disable revokes all
// refresh token families of the client.
func (a *Admin) UpdateClient(ctx context.Context, actor, id string, in UpdateClientInput) (ClientView, error) {
	err := a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		c, err := a.d.Clients.LockByID(ctx, id)
		if errors.Is(err, clients.ErrNotFound) {
			return apperrors.NewNotFound("the client does not exist")
		}
		if err != nil {
			return err
		}
		if c.Source == domain.SourceConfig {
			return errManagedByConfig()
		}
		if in.Type != nil && *in.Type != c.Type {
			return apperrors.NewUnprocessable("client_type_immutable", "the type of a client cannot change")
		}
		if in.Name != nil {
			n, err := checkClientName(*in.Name)
			if err != nil {
				return err
			}
			c.Name = n
		}
		var fields []domain.FieldError
		if in.RedirectURIs != nil || in.PostLogoutRedirectURIs != nil {
			if c.Type != domain.ClientTypePublic {
				return errTypeUnsupported()
			}
		}
		if in.RedirectURIs != nil {
			fields = append(fields, domain.CheckRedirectURIs("redirectUris", *in.RedirectURIs)...)
			if len(*in.RedirectURIs) == 0 {
				fields = append(fields, domain.FieldError{Code: "invalid_redirect_uri", Field: "redirectUris", Message: "a public client needs a redirect URI"})
			}
			c.RedirectURIs = *in.RedirectURIs
		}
		if in.PostLogoutRedirectURIs != nil {
			fields = append(fields, domain.CheckRedirectURIs("postLogoutRedirectUris", *in.PostLogoutRedirectURIs)...)
			c.PostLogoutRedirectURIs = *in.PostLogoutRedirectURIs
		}
		if err := validationErr(fields); err != nil {
			return err
		}
		disabling := in.Disabled != nil && *in.Disabled && !c.Disabled
		if in.Disabled != nil {
			c.Disabled = *in.Disabled
		}
		if err := a.d.Clients.Update(ctx, c); err != nil {
			return err
		}
		if disabling {
			if err := a.d.Refresh.RevokeClientFamilies(ctx, id, a.now()); err != nil {
				return err
			}
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionClientUpdate, targetClient, id, map[string]any{"fields": clientFields(in)})
	}, txName("update_client"))
	if err != nil {
		return ClientView{}, err
	}
	a.LogChange(ctx, actor, "Clients_update", id)
	return a.GetClient(ctx, id)
}

// AddClientKey adds a public key to a service client.
func (a *Admin) AddClientKey(ctx context.Context, actor, clientID string, in JWKInput) (domain.ClientKey, error) {
	c, err := a.getClient(ctx, clientID)
	if err != nil {
		return domain.ClientKey{}, err
	}
	if c.Source == domain.SourceConfig {
		return domain.ClientKey{}, errManagedByConfig()
	}
	if c.Type != domain.ClientTypeService {
		return domain.ClientKey{}, errTypeUnsupported()
	}
	k, err := checkJWK(in)
	if err != nil {
		return domain.ClientKey{}, err
	}
	k.ClientID, k.CreatedAt = clientID, a.now()
	err = a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := a.d.Clients.AddKey(ctx, k); err != nil {
			return err
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionClientKeyAdd, targetClient, clientID, map[string]any{"kid": k.KID})
	}, txName("add_client_key"))
	if errors.Is(err, clients.ErrKeyExists) {
		return domain.ClientKey{}, apperrors.NewConflictCode("key_exists", "the client has a key with this kid")
	} else if err != nil {
		return domain.ClientKey{}, fmt.Errorf("add the key: %w", err)
	}
	a.LogChange(ctx, actor, "ClientKeys_add", clientID)
	return k, nil
}

// RemoveClientKey removes a key of a service client.
func (a *Admin) RemoveClientKey(ctx context.Context, actor, clientID, kid string) error {
	c, err := a.getClient(ctx, clientID)
	if err != nil {
		return err
	}
	if c.Source == domain.SourceConfig {
		return errManagedByConfig()
	}
	if c.Type != domain.ClientTypeService {
		return errTypeUnsupported()
	}
	err = a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		deleted, err := a.d.Clients.DeleteKey(ctx, clientID, kid)
		if err != nil {
			return fmt.Errorf("remove the key: %w", err)
		}
		if !deleted {
			return apperrors.NewNotFound("the client does not have this key")
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionClientKeyRemove, targetClient, clientID, map[string]any{"kid": kid})
	}, txName("remove_client_key"))
	if err != nil {
		return err
	}
	a.LogChange(ctx, actor, "ClientKeys_remove", clientID)
	return nil
}

func (a *Admin) serviceClient(ctx context.Context, id string) (domain.Client, error) {
	c, err := a.getClient(ctx, id)
	if err != nil {
		return domain.Client{}, err
	}
	if c.Type != domain.ClientTypeService {
		return domain.Client{}, errTypeUnsupported()
	}
	return c, nil
}

// ListClientRoles returns a page of the role assignments of a service client.
// The list has the implicit role identity:service.
func (a *Admin) ListClientRoles(ctx context.Context, clientID string, p ListPage) (Page[domain.RoleAssignment], error) {
	n, err := p.size()
	if err != nil {
		return Page[domain.RoleAssignment]{}, err
	}
	cur, err := DecodeRoleCursor(p.Token)
	if err != nil {
		return Page[domain.RoleAssignment]{}, err
	}
	if _, err := a.serviceClient(ctx, clientID); err != nil {
		return Page[domain.RoleAssignment]{}, err
	}
	all, err := a.d.ClientRoles.Assignments(ctx, clientID)
	if err != nil {
		return Page[domain.RoleAssignment]{}, fmt.Errorf("list client roles: %w", err)
	}
	if !slices.ContainsFunc(all, func(x domain.RoleAssignment) bool { return x.Role == domain.ServiceRole }) {
		all = append(all, domain.RoleAssignment{Role: domain.ServiceRole, Source: domain.AssignmentConfig})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Role.App != all[j].Role.App {
			return all[i].Role.App < all[j].Role.App
		}
		return all[i].Role.Role < all[j].Role.Role
	})
	var rest []domain.RoleAssignment
	for _, x := range all {
		if cur == nil || x.Role.App > cur.App || x.Role.App == cur.App && x.Role.Role > cur.Role {
			rest = append(rest, x)
		}
	}
	if len(rest) > n+1 {
		rest = rest[:n+1]
	}
	return rolePage(rest, n), nil
}

// AssignClientRole gives a role to a service client. A client of the clients
// file can get extra roles by the API.
func (a *Admin) AssignClientRole(ctx context.Context, actor, clientID string, ref domain.RoleRef) (domain.RoleAssignment, error) {
	if _, err := a.serviceClient(ctx, clientID); err != nil {
		return domain.RoleAssignment{}, err
	}
	if err := a.roleExists(ctx, ref); err != nil {
		return domain.RoleAssignment{}, err
	}
	err := a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := a.d.ClientRoles.Assign(ctx, clientID, ref, domain.AssignmentAPI); err != nil {
			return err
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionClientRoleAssign, targetClient, clientID, map[string]any{"role": ref.String()})
	}, txName("assign_client_role"))
	if err != nil {
		return domain.RoleAssignment{}, err
	}
	a.LogChange(ctx, actor, "ClientRoles_assign", clientID)
	all, err := a.d.ClientRoles.Assignments(ctx, clientID)
	if err != nil {
		return domain.RoleAssignment{}, err
	}
	for _, x := range all {
		if x.Role == ref {
			return x, nil
		}
	}
	return domain.RoleAssignment{Role: ref, Source: domain.AssignmentAPI}, nil
}

// RemoveClientRole removes an assignment with the source api. An assignment of
// the clients file gives client_managed_by_config.
func (a *Admin) RemoveClientRole(ctx context.Context, actor, clientID string, ref domain.RoleRef) error {
	if _, err := a.serviceClient(ctx, clientID); err != nil {
		return err
	}
	all, err := a.d.ClientRoles.Assignments(ctx, clientID)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(all, func(x domain.RoleAssignment) bool { return x.Role == ref })
	if i < 0 {
		return apperrors.NewNotFound("the client does not have the role")
	}
	if all[i].Source == domain.AssignmentConfig {
		return errManagedByConfig()
	}
	err = a.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if _, err := a.d.ClientRoles.Delete(ctx, clientID, ref); err != nil {
			return err
		}
		return writeAudit(ctx, a.d.Audit, a.now(), ActionClientRoleRemove, targetClient, clientID, map[string]any{"role": ref.String()})
	}, txName("remove_client_role"))
	if err != nil {
		return err
	}
	a.LogChange(ctx, actor, "ClientRoles_remove", clientID)
	return nil
}

// clientFields returns the names of the fields that a client change sets.
func clientFields(in UpdateClientInput) []string {
	var out []string
	if in.Name != nil {
		out = append(out, "name")
	}
	if in.RedirectURIs != nil {
		out = append(out, "redirectUris")
	}
	if in.PostLogoutRedirectURIs != nil {
		out = append(out, "postLogoutRedirectUris")
	}
	if in.Disabled != nil {
		out = append(out, "disabled")
	}
	return out
}
