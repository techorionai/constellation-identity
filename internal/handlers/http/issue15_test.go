package httpapi_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/auth"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	"github.com/techorionai/constellation-identity/internal/domain"
	httpapi "github.com/techorionai/constellation-identity/internal/handlers/http"
	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

const (
	pkOwn      = "22222222-2222-4222-8222-2222222222e1"
	pkSecond   = "22222222-2222-4222-8222-2222222222e2"
	pkOfOther  = "22222222-2222-4222-8222-2222222222e3"
	pkUnknown  = "22222222-2222-4222-8222-2222222222ee"
	scopeOwn   = "identity:mfa:manage_own"
	scopeMFARd = "identity:mfa:read"
)

// passkeyVerifier gives a principal for each test token of the passkey tests.
type passkeyVerifier struct{}

func (passkeyVerifier) Verify(_ context.Context, token string) (auth.Principal, error) {
	fresh := mfaNow.Add(-time.Minute)
	stale := mfaNow.Add(-staleMinutes * time.Minute)
	user := func(id string, scopes []string, at time.Time, amr ...string) auth.Principal {
		return auth.Principal{ID: id, Type: auth.PrincipalUser, Scopes: scopes, Audience: "identity", AuthMethods: amr, AuthTime: at}
	}
	own := []string{scopeOwn}
	switch token {
	case "user-fresh":
		return user(mfaUser, own, fresh, "hwk", "user", "mfa"), nil
	case "user-stale":
		return user(mfaUser, own, stale, "hwk", "user", "mfa"), nil
	case "user-nomfa":
		return user(mfaUser, own, fresh, "pwd"), nil
	case "user-noscope-stale":
		return user(mfaUser, []string{scopeUserRd}, stale, "pwd"), nil
	case "user-acting":
		return auth.Principal{ID: mfaUser, Type: auth.PrincipalUser, Scopes: own, Audience: "identity", Act: &auth.Actor{ID: "agent", Type: auth.PrincipalAgent}}, nil
	case "user-api":
		return auth.Principal{ID: mfaUser, Type: auth.PrincipalUser, Scopes: own, Audience: "identity", TokenType: auth.TokenTypeAPI}, nil
	case "service-stale":
		return auth.Principal{ID: "demo", Type: auth.PrincipalService, Scopes: own, Audience: "identity", AuthTime: stale}, nil
	case "agent":
		return auth.Principal{ID: "agent", Type: auth.PrincipalAgent, Scopes: own, Audience: "identity"}, nil
	case "admin-own":
		return user(mfaAdmin, own, fresh, "hwk", "user", "mfa"), nil
	case "reader":
		return user(mfaAdmin, []string{scopeUserRd}, fresh, "mfa"), nil
	case "mfa-reader":
		return user(mfaAdmin, []string{scopeMFARd}, fresh, "mfa"), nil
	}
	return auth.Principal{}, auth.ErrInvalidToken
}

type passkeyRig struct {
	h      http.Handler
	keys   *mock.Passkeys
	events *mock.Events
	sess   *mock.Sessions
}

func newPasskeyRig(t *testing.T, on bool) *passkeyRig {
	t.Helper()
	users := mock.NewUsers()
	for id, email := range map[string]string{mfaUser: "u@example.com", mfaOther: "o@example.com", mfaAdmin: "a@example.com"} {
		users.Rows[id] = domain.User{ID: id, Email: email, Name: id, Status: domain.UserActive}
	}
	roles := mock.NewUserRoles(users)
	roles.Perms[domain.AdminRole] = []string{domain.AdminPermission}
	roles.Rows[mfaAdmin] = []domain.RoleRef{domain.AdminRole}
	r := &passkeyRig{keys: mock.NewPasskeys(), events: &mock.Events{}, sess: mock.NewSessions()}
	repo := mock.NewMFA()
	repo.Passkeys = r.keys
	cmd, err := commands.NewMFA(commands.MFADeps{
		Users: users, UserRoles: roles, Sessions: r.sess, MFA: repo, Sealer: mock.Sealer{}, Pending: mock.NewPending(),
		Passkeys: r.keys, WebAuthn: &mock.WebAuthn{}, Ceremonies: mock.NewCeremonies(), PasskeysOn: on,
		Setups: mock.NewSetups(), Failures: mock.NewFailures(), Limiter: mock.NewLimiter(), Events: r.events, Tx: mock.Tx{},
		RequireMFAForAdmins: true, Issuer: "Constellation", MaxFailures: 10, FailureWindow: time.Minute,
		Log: slog.New(slog.NewTextHandler(devNull{}, nil)), Now: func() time.Time { return mfaNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.h = httpapi.New(httpapi.Deps{
		JWKS: queries.NewGetJWKS(fakeKeys{}), Discovery: queries.NewGetDiscovery("https://id.example.com"),
		Verifier: passkeyVerifier{}, Scopes: realScopes(t), MFA: cmd, Now: func() time.Time { return mfaNow },
	}).Handler()
	add := func(id, user, name string, at time.Time, used *time.Time, synced bool) {
		r.keys.Add(domain.PasskeyCredential{
			Passkey:      domain.Passkey{ID: id, UserID: user, Name: name, CreatedAt: at, LastUsedAt: used, BackupState: synced},
			CredentialID: []byte("credential-" + id), PublicKey: []byte("public-key-" + id), SignCount: 3, AAGUID: []byte("aaguid"),
		})
	}
	used := mfaNow.Add(-time.Hour)
	add(pkOwn, mfaUser, "Laptop", mfaNow.Add(-3*time.Hour), nil, true)
	add(pkSecond, mfaUser, "Phone", mfaNow.Add(-2*time.Hour), &used, false)
	add(pkOfOther, mfaOther, "Other", mfaNow.Add(-time.Hour), nil, false)
	return r
}

// U15: the mapping of a passkey. lastUsedAt is absent when NULL, synced is the
// backup state, and no key material is in the answer.
func TestIssue15_U15_PasskeyMapping(t *testing.T) {
	r := newPasskeyRig(t, true)
	rec := call(r.h, http.MethodGet, "/v1/me/passkeys", "user-fresh", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var page struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Items) != 2 {
		t.Fatalf("page = %s, %v", rec.Body, err)
	}
	first, second := page.Items[0], page.Items[1]
	if first["id"] != pkOwn || first["name"] != "Laptop" || first["synced"] != true {
		t.Errorf("first = %v", first)
	}
	if _, has := first["lastUsedAt"]; has {
		t.Errorf("lastUsedAt must be absent when NULL: %v", first)
	}
	if second["id"] != pkSecond || second["synced"] != false || second["lastUsedAt"] == nil {
		t.Errorf("second = %v", second)
	}
	for _, key := range []string{"credentialId", "publicKey", "signCount", "userHandle"} {
		if _, has := first[key]; has {
			t.Errorf("the answer has %s", key)
		}
	}
	if body := rec.Body.String(); strings.Contains(body, "credential-") || strings.Contains(body, "public-key") {
		t.Errorf("key material in the answer: %s", body)
	}
}

// I23, I24: the order of the checks of MePasskeys_remove, and the answer of
// each token type that is not a user token.
func TestIssue15_RemoveOrder(t *testing.T) {
	r := newPasskeyRig(t, true)
	path := "/v1/me/passkeys/" + pkOwn
	for _, tok := range []string{"user-acting", "user-api", "agent"} {
		wantProblem(t, "remove with "+tok, call(r.h, http.MethodDelete, path, tok, ""), http.StatusForbidden, "user_token_required")
	}
	// A service token with an old auth_time: 403 before 401.
	wantProblem(t, "service token", call(r.h, http.MethodDelete, path, "service-stale", ""), http.StatusForbidden, "user_token_required")
	// Without the scope: 403 before 401.
	if rec := call(r.h, http.MethodDelete, path, "user-noscope-stale", ""); rec.Code != http.StatusForbidden || codeOf(t, rec) == "reauthentication_required" {
		t.Fatalf("no scope: %d %s", rec.Code, rec.Body)
	}
	// An old token and an unknown ID: 401 before 404.
	wantReauth(t, "stale token, unknown passkey", call(r.h, http.MethodDelete, "/v1/me/passkeys/"+pkUnknown, "user-stale", ""))
	wantReauth(t, "token with no mfa", call(r.h, http.MethodDelete, path, "user-nomfa", ""))
	// A fresh token: 404 for an unknown passkey, for a passkey of another user, and for an ID that is not a UUID.
	for _, id := range []string{pkUnknown, pkOfOther, "abc"} {
		wantProblem(t, "remove "+id, call(r.h, http.MethodDelete, "/v1/me/passkeys/"+id, "user-fresh", ""), http.StatusNotFound, "passkey_not_found")
	}
	if n, _ := r.keys.Count(context.Background(), mfaOther); n != 1 {
		t.Fatal("the passkey of another user must stay")
	}
	// A fresh token removes the passkey.
	if rec := call(r.h, http.MethodDelete, path, "user-fresh", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if len(r.events.Audits) != 1 || r.events.Audits[0].Action != securityevents.ActionPasskeyRemove || len(r.events.Notices) != 1 {
		t.Fatalf("events = %+v %+v", r.events.Audits, r.events.Notices)
	}
}

// I24: an admin whose only second factor is the passkey cannot remove it.
func TestIssue15_RemoveLastFactorOfAdmin(t *testing.T) {
	r := newPasskeyRig(t, true)
	r.keys.Add(domain.PasskeyCredential{Passkey: domain.Passkey{ID: pkUnknown, UserID: mfaAdmin, Name: "Admin key", CreatedAt: mfaNow}, CredentialID: []byte("admin-key")})
	wantProblem(t, "last factor", call(r.h, http.MethodDelete, "/v1/me/passkeys/"+pkUnknown, "admin-own", ""), http.StatusConflict, "mfa_required")
	// With passkeys off, the stored passkey does not count, so the removal works.
	off := newPasskeyRig(t, false)
	off.keys.Add(domain.PasskeyCredential{Passkey: domain.Passkey{ID: pkUnknown, UserID: mfaAdmin, Name: "Admin key", CreatedAt: mfaNow}, CredentialID: []byte("admin-key")})
	if rec := call(off.h, http.MethodDelete, "/v1/me/passkeys/"+pkUnknown, "admin-own", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("remove with passkeys off: %d %s", rec.Code, rec.Body)
	}
}

// I25, I34: the order of the checks of MePasskeys_update: the token, the scopes,
// user_token_required, the step-up, passkey_not_found, and the name (422).
func TestIssue15_UpdateOrder(t *testing.T) {
	r := newPasskeyRig(t, true)
	path := "/v1/me/passkeys/" + pkOwn
	body := `{"name":"Renamed"}`
	for _, tok := range []string{"user-acting", "user-api", "agent", "service-stale"} {
		wantProblem(t, "update with "+tok, call(r.h, http.MethodPatch, path, tok, body), http.StatusForbidden, "user_token_required")
	}
	wantReauth(t, "stale token", call(r.h, http.MethodPatch, path, "user-stale", body))
	wantReauth(t, "token with no mfa", call(r.h, http.MethodPatch, path, "user-nomfa", body))
	wantReauth(t, "stale token, unknown passkey, bad name", call(r.h, http.MethodPatch, "/v1/me/passkeys/"+pkUnknown, "user-stale", `{"name":"a\nb"}`))
	// A fresh token: 404 comes before 422.
	for _, id := range []string{pkOfOther, "abc", pkUnknown} {
		wantProblem(t, "update "+id, call(r.h, http.MethodPatch, "/v1/me/passkeys/"+id, "user-fresh", body), http.StatusNotFound, "passkey_not_found")
		wantProblem(t, "update "+id+" with a bad name", call(r.h, http.MethodPatch, "/v1/me/passkeys/"+id, "user-fresh", `{"name":"a\nb"}`), http.StatusNotFound, "passkey_not_found")
	}
	rec := call(r.h, http.MethodPatch, path, "user-fresh", `{"name":"a\nb"}`)
	if rec.Code != http.StatusUnprocessableEntity || codeOf(t, rec) != "invalid_name" {
		t.Fatalf("bad name: %d %s", rec.Code, rec.Body)
	}
	if len(r.events.Audits) != 0 {
		t.Fatalf("a refusal wrote an audit entry: %+v", r.events.Audits)
	}
	rec = call(r.h, http.MethodPatch, path, "user-fresh", body)
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || got["name"] != "Renamed" || got["id"] != pkOwn {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if len(r.events.Audits) != 1 || r.events.Audits[0].Action != securityevents.ActionPasskeyRename ||
		r.events.Audits[0].Changes["old_name"] != "Laptop" || r.events.Audits[0].Changes["new_name"] != "Renamed" {
		t.Fatalf("audits = %+v", r.events.Audits)
	}
}

// I22: the scopes of UserPasskeys_list.
func TestIssue15_UserPasskeysList(t *testing.T) {
	r := newPasskeyRig(t, true)
	if rec := call(r.h, http.MethodGet, "/v1/users/"+mfaUser+"/passkeys", "reader", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("identity:user:read only: %d", rec.Code)
	}
	rec := call(r.h, http.MethodGet, "/v1/users/"+mfaUser+"/passkeys", "mfa-reader", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Laptop") {
		t.Fatalf("identity:mfa:read: %d %s", rec.Code, rec.Body)
	}
	wantProblem(t, "unknown user", call(r.h, http.MethodGet, "/v1/users/"+mfaUnknown+"/passkeys", "mfa-reader", ""), http.StatusNotFound, "user_not_found")
	// The list of the user, not of another user.
	if rec := call(r.h, http.MethodGet, "/v1/users/"+mfaOther+"/passkeys", "mfa-reader", ""); strings.Contains(rec.Body.String(), "Laptop") {
		t.Fatalf("list of another user: %s", rec.Body)
	}
	// With passkeys off, the list stays.
	off := newPasskeyRig(t, false)
	if rec := call(off.h, http.MethodGet, "/v1/me/passkeys", "user-fresh", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Laptop") {
		t.Fatalf("list with passkeys off: %d %s", rec.Code, rec.Body)
	}
}

// I28: the order and the cursor of the list.
func TestIssue15_ListCursor(t *testing.T) {
	r := newPasskeyRig(t, true)
	// Three passkeys with the same creation time and two more.
	for _, id := range []string{"22222222-2222-4222-8222-2222222222a3", "22222222-2222-4222-8222-2222222222a1", "22222222-2222-4222-8222-2222222222a2"} {
		r.keys.Add(domain.PasskeyCredential{Passkey: domain.Passkey{ID: id, UserID: mfaOther, Name: id, CreatedAt: mfaNow}, CredentialID: []byte(id)})
	}
	page := func(path string) (ids []string, next string) {
		rec := call(r.h, http.MethodGet, path, "mfa-reader", "")
		var p struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		for _, i := range p.Items {
			ids = append(ids, i.ID)
		}
		return ids, p.NextPageToken
	}
	// pkOfOther is older than the three, so it comes first.
	first, next := page("/v1/users/" + mfaOther + "/passkeys?pageSize=2")
	if len(first) != 2 || first[0] != pkOfOther || first[1] != "22222222-2222-4222-8222-2222222222a1" || next == "" {
		t.Fatalf("page 1 = %v %q", first, next)
	}
	second, next := page("/v1/users/" + mfaOther + "/passkeys?pageSize=2&pageToken=" + next)
	if len(second) != 2 || second[0] != "22222222-2222-4222-8222-2222222222a2" || second[1] != "22222222-2222-4222-8222-2222222222a3" || next != "" {
		t.Fatalf("page 2 = %v %q", second, next)
	}
}

var _ = httptest.NewRecorder
