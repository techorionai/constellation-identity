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
	mfaUser      = "11111111-1111-4111-8111-1111111111aa"
	mfaOther     = "11111111-1111-4111-8111-1111111111bb"
	mfaAdmin     = "11111111-1111-4111-8111-1111111111cc"
	mfaUnknown   = "11111111-1111-4111-8111-1111111111ee"
	challenge    = `Bearer error="insufficient_user_authentication", error_description="A fresh MFA login is necessary", max_age="300"`
	scopeManage  = "identity:mfa:manage_own"
	scopeRead    = "identity:mfa:read"
	scopeReset   = "identity:mfa:reset"
	scopeAdmin   = "identity:admin"
	scopeUserRd  = "identity:user:read"
	scopeUserWr  = "identity:user:write"
	staleMinutes = 6
)

var mfaNow = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

// mfaVerifier gives a principal for each test token.
type mfaVerifier struct{}

func (mfaVerifier) Verify(_ context.Context, token string) (auth.Principal, error) {
	fresh := mfaNow.Add(-time.Minute)
	stale := mfaNow.Add(-staleMinutes * time.Minute)
	user := func(id string, scopes []string, at time.Time) auth.Principal {
		return auth.Principal{
			ID: id, Type: auth.PrincipalUser, Scopes: scopes, Audience: "identity",
			AuthMethods: []string{"pwd", "otp", "mfa"}, AuthTime: at,
		}
	}
	switch token {
	case "user-fresh":
		return user(mfaUser, []string{scopeManage}, fresh), nil
	case "user-stale":
		return user(mfaUser, []string{scopeManage}, stale), nil
	case "user-noscope-stale":
		return user(mfaUser, []string{scopeUserRd}, stale), nil
	case "user-nomfa":
		p := user(mfaUser, []string{scopeManage}, fresh)
		p.AuthMethods = []string{"pwd"}
		return p, nil
	case "user-acting":
		// R6: the adapter of platform-go gives no methods and no time to a token with act.
		return auth.Principal{
			ID: mfaUser, Type: auth.PrincipalUser, Scopes: []string{scopeManage}, Audience: "identity",
			Act: &auth.Actor{ID: "agent", Type: auth.PrincipalAgent},
		}, nil
	case "user-api":
		return auth.Principal{
			ID: mfaUser, Type: auth.PrincipalUser, Scopes: []string{scopeManage}, Audience: "identity", TokenType: auth.TokenTypeAPI,
		}, nil
	case "admin-fresh":
		return user(mfaAdmin, []string{scopeReset, scopeAdmin, scopeRead}, fresh), nil
	case "admin-stale":
		return user(mfaAdmin, []string{scopeReset, scopeAdmin, scopeRead}, stale), nil
	case "admin-acting":
		return auth.Principal{
			ID: mfaAdmin, Type: auth.PrincipalUser, Scopes: []string{scopeReset, scopeAdmin}, Audience: "identity",
			Act: &auth.Actor{ID: "agent", Type: auth.PrincipalAgent},
		}, nil
	case "admin-api":
		return auth.Principal{
			ID: mfaAdmin, Type: auth.PrincipalUser, Scopes: []string{scopeReset, scopeAdmin}, Audience: "identity", TokenType: auth.TokenTypeAPI,
		}, nil
	case "writer-stale":
		return user(mfaAdmin, []string{scopeUserWr}, stale), nil
	case "reader":
		return user(mfaAdmin, []string{scopeUserRd}, fresh), nil
	}
	return auth.Principal{}, auth.ErrInvalidToken
}

type mfaRig struct {
	h      http.Handler
	mfa    *mock.MFA
	events *mock.Events
	sess   *mock.Sessions
}

func newMFARig(t *testing.T) *mfaRig {
	t.Helper()
	users := mock.NewUsers()
	for id, email := range map[string]string{mfaUser: "u@example.com", mfaOther: "o@example.com", mfaAdmin: "a@example.com"} {
		users.Rows[id] = domain.User{ID: id, Email: email, Name: id, Status: domain.UserActive}
	}
	roles := mock.NewUserRoles(users)
	roles.Perms[domain.AdminRole] = []string{domain.AdminPermission}
	roles.Rows[mfaAdmin] = []domain.RoleRef{domain.AdminRole}
	r := &mfaRig{mfa: mock.NewMFA(), events: &mock.Events{}, sess: mock.NewSessions()}
	cmd, err := commands.NewMFA(commands.MFADeps{
		Users: users, UserRoles: roles, Sessions: r.sess, MFA: r.mfa, Sealer: mock.Sealer{}, Pending: mock.NewPending(),
		Setups: mock.NewSetups(), Failures: mock.NewFailures(), Limiter: mock.NewLimiter(), Events: r.events, Tx: mock.Tx{},
		RequireMFAForAdmins: true, Issuer: "Constellation", MaxFailures: 10, FailureWindow: time.Minute,
		Log: slog.New(slog.NewTextHandler(devNull{}, nil)), Now: func() time.Time { return mfaNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.h = httpapi.New(httpapi.Deps{
		JWKS: queries.NewGetJWKS(fakeKeys{}), Discovery: queries.NewGetDiscovery("https://id.example.com"),
		Verifier: mfaVerifier{}, Scopes: realScopes(t), MFA: cmd, Now: func() time.Time { return mfaNow },
	}).Handler()
	return r
}

type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }

// enable gives a user a TOTP factor and recovery codes.
func (r *mfaRig) enable(t *testing.T, userID string) {
	t.Helper()
	if err := r.mfa.EnableTOTP(context.Background(), domain.TOTPRecord{UserID: userID, Secret: []byte("s"), CreatedAt: mfaNow.Add(-time.Hour)},
		[][]byte{[]byte("h1"), []byte("h2")}, mfaNow); err != nil {
		t.Fatal(err)
	}
}

func (r *mfaRig) has(userID string) bool {
	st, _ := r.mfa.State(context.Background(), userID)
	return st.HasTOTP
}

// wantReauth checks the 401 refusal: the status, the content type, the exact
// challenge, and the body.
func wantReauth(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("%s: status %d, body %s", what, rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("%s: content type %q", what, got)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != challenge {
		t.Errorf("%s: WWW-Authenticate %q", what, got)
	}
	var b map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b["type"] != "about:blank" || b["title"] != "Reauthentication required" || b["status"] != float64(401) ||
		b["code"] != "reauthentication_required" || b["detail"] != "A fresh MFA login is necessary." {
		t.Errorf("%s: body %v", what, b)
	}
}

func wantProblem(t *testing.T, what string, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status || codeOf(t, rec) != code {
		t.Fatalf("%s: status %d, body %s, want %d %s", what, rec.Code, rec.Body, status, code)
	}
}

func codeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return p.Code
}

// I12 (form of the refusal), I21, I23, I25, I26: the 401 refusal is the same
// for each operation and each reason.
func TestI12_ReauthenticationRefusal(t *testing.T) {
	r := newMFARig(t)
	r.enable(t, mfaUser)
	r.enable(t, mfaOther)
	rec := call(r.h, http.MethodDelete, "/v1/me/totp", "user-stale", "")
	wantReauth(t, "stale user token", rec)
	if !r.has(mfaUser) {
		t.Fatal("TOTP must stay")
	}
	// I21: a stale admin token, and an API token of the admin.
	for _, tok := range []string{"admin-stale", "admin-api"} {
		rec = call(r.h, http.MethodDelete, "/v1/users/"+mfaOther+"/mfa", tok, "")
		wantReauth(t, "reset with "+tok, rec)
		if !r.has(mfaOther) {
			t.Fatalf("%s: TOTP of the user must stay", tok)
		}
	}
	// I26: an agent exchange token (with act, no methods, no time).
	rec = call(r.h, http.MethodDelete, "/v1/users/"+mfaOther+"/mfa", "admin-acting", "")
	wantReauth(t, "reset with act", rec)
	if !r.has(mfaOther) {
		t.Fatal("TOTP of the user must stay")
	}
	// A token with no mfa in the methods gets the same refusal.
	wantReauth(t, "no mfa", call(r.h, http.MethodDelete, "/v1/me/totp", "user-nomfa", ""))
	if len(r.events.Audits) != 0 || len(r.events.Notices) != 0 {
		t.Fatal("a refused call must not call the port")
	}
}

// I14, I34: an exchange token (with act) gives 403 user_token_required before 401.
// An API token and a service token give the same.
func TestI14_I34_UserTokenRequired(t *testing.T) {
	r := newMFARig(t)
	r.enable(t, mfaUser)
	for _, tok := range []string{"user-acting", "user-api"} {
		wantProblem(t, "remove with "+tok, call(r.h, http.MethodDelete, "/v1/me/totp", tok, ""), http.StatusForbidden, "user_token_required")
		wantProblem(t, "get with "+tok, call(r.h, http.MethodGet, "/v1/me/mfa", tok, ""), http.StatusForbidden, "user_token_required")
	}
	if !r.has(mfaUser) {
		t.Fatal("TOTP must stay")
	}
}

// I16, I22: the scope check comes before the 401.
func TestI16_I22_ScopeBeforeReauth(t *testing.T) {
	r := newMFARig(t)
	r.enable(t, mfaOther)
	wantProblem(t, "reset with user:write", call(r.h, http.MethodDelete, "/v1/users/"+mfaOther+"/mfa", "writer-stale", ""), http.StatusForbidden, "insufficient_scope")
	wantProblem(t, "remove without manage_own", call(r.h, http.MethodDelete, "/v1/me/totp", "user-noscope-stale", ""), http.StatusForbidden, "insufficient_scope")
	if !r.has(mfaOther) {
		t.Fatal("TOTP must stay")
	}
}

// I23: a stale token and a user with no TOTP gives 401 before 404.
func TestI23_ReauthBeforeNotFound(t *testing.T) {
	r := newMFARig(t)
	wantReauth(t, "stale, no totp", call(r.h, http.MethodDelete, "/v1/me/totp", "user-stale", ""))
	wantProblem(t, "fresh, no totp", call(r.h, http.MethodDelete, "/v1/me/totp", "user-fresh", ""), http.StatusNotFound, "totp_not_found")
}

// I13 (handler form): a fresh token of a user that does not need MFA gives 204.
func TestI13_RemoveTOTP(t *testing.T) {
	r := newMFARig(t)
	r.enable(t, mfaUser)
	rec := call(r.h, http.MethodDelete, "/v1/me/totp", "user-fresh", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	rec = call(r.h, http.MethodGet, "/v1/me/mfa", "user-fresh", "")
	var b map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	if _, has := b["totp"]; has || b["enabled"] != false || b["recoveryCodesRemaining"] != float64(0) || b["required"] != false {
		t.Fatalf("status = %v", b)
	}
	if !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("body %s", rec.Body)
	}
}

// I35, I36, I32: the self reset gives 409 after the 401 and the 404.
func TestI35_I36_SelfReset(t *testing.T) {
	r := newMFARig(t)
	r.enable(t, mfaAdmin)
	wantProblem(t, "self reset", call(r.h, http.MethodDelete, "/v1/users/"+mfaAdmin+"/mfa", "admin-fresh", ""), http.StatusConflict, "mfa_required")
	if !r.has(mfaAdmin) {
		t.Fatal("TOTP of the admin must stay")
	}
	// I36: 401 before 409, and 404 before 409.
	wantReauth(t, "stale self reset", call(r.h, http.MethodDelete, "/v1/users/"+mfaAdmin+"/mfa", "admin-stale", ""))
	wantProblem(t, "unknown user", call(r.h, http.MethodDelete, "/v1/users/"+mfaUnknown+"/mfa", "admin-fresh", ""), http.StatusNotFound, "user_not_found")
	wantProblem(t, "bad user ID", call(r.h, http.MethodDelete, "/v1/users/x/mfa", "admin-fresh", ""), http.StatusNotFound, "user_not_found")
	if len(r.events.Audits) != 0 {
		t.Fatal("a refused reset must not call the port")
	}
}

// I31, I32, I33, I38: UserMfa_get uses identity:mfa:read.
func TestI31_I33_I38_UserMfaGet(t *testing.T) {
	r := newMFARig(t)
	r.enable(t, mfaOther)
	rec := call(r.h, http.MethodGet, "/v1/users/"+mfaOther+"/mfa", "admin-fresh", "")
	var b map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &b) != nil {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	totp, _ := b["totp"].(map[string]any)
	if b["enabled"] != true || b["required"] != false || b["recoveryCodesRemaining"] != float64(2) || totp["createdAt"] == nil {
		t.Fatalf("status = %v", b)
	}
	if _, has := totp["lastUsedAt"]; has {
		t.Fatal("lastUsedAt must be absent")
	}
	// The admin needs MFA: required is true.
	rec = call(r.h, http.MethodGet, "/v1/users/"+mfaAdmin+"/mfa", "admin-fresh", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil || b["required"] != true {
		t.Fatalf("admin status = %v", b)
	}
	wantProblem(t, "unknown user", call(r.h, http.MethodGet, "/v1/users/"+mfaUnknown+"/mfa", "admin-fresh", ""), http.StatusNotFound, "user_not_found")
	// I33, I38: identity:user:read is not enough.
	wantProblem(t, "user:read only", call(r.h, http.MethodGet, "/v1/users/"+mfaOther+"/mfa", "reader", ""), http.StatusForbidden, "insufficient_scope")
	if rec := call(r.h, http.MethodGet, "/v1/users/"+mfaOther+"/mfa", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
}

// I40 (handler form): a good removal and a good reset write one audit entry and
// one notice each.
func TestI40_SecurityEvents(t *testing.T) {
	r := newMFARig(t)
	r.enable(t, mfaUser)
	r.enable(t, mfaOther)
	if rec := call(r.h, http.MethodDelete, "/v1/me/totp", "user-fresh", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if rec := call(r.h, http.MethodDelete, "/v1/users/"+mfaOther+"/mfa", "admin-fresh", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	if len(r.events.Audits) != 2 || len(r.events.Notices) != 2 {
		t.Fatalf("audits = %d, notices = %d", len(r.events.Audits), len(r.events.Notices))
	}
	a0, a1 := r.events.Audits[0], r.events.Audits[1]
	if a0.Action != securityevents.ActionTotpRemove || a0.Actor != mfaUser || a0.TargetUserID != mfaUser ||
		a1.Action != securityevents.ActionMfaReset || a1.Actor != mfaAdmin || a1.TargetUserID != mfaOther {
		t.Fatalf("audits = %+v", r.events.Audits)
	}
}

// I30 (handler form): a reset for a user with no factor gives 204.
func TestI30_ResetNoFactor(t *testing.T) {
	r := newMFARig(t)
	if rec := call(r.h, http.MethodDelete, "/v1/users/"+mfaOther+"/mfa", "admin-fresh", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
}
