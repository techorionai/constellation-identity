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
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

const (
	freshChallenge = `Bearer error="insufficient_user_authentication", error_description="A fresh login is necessary", max_age="300"`
	scopeLinkOwn   = "identity:identity_link:manage_own"
	scopeLinkRead  = "identity:identity_link:read"
	scopeLinkRm    = "identity:identity_link:remove"
)

// linkVerifier gives a principal for each test token.
type linkVerifier struct{}

func (linkVerifier) Verify(_ context.Context, token string) (auth.Principal, error) {
	fresh := mfaNow.Add(-time.Minute)
	stale := mfaNow.Add(-staleMinutes * time.Minute)
	user := func(id string, scopes []string, methods []string, at time.Time) auth.Principal {
		return auth.Principal{ID: id, Type: auth.PrincipalUser, Scopes: scopes, Audience: "identity", AuthMethods: methods, AuthTime: at}
	}
	own := []string{scopeLinkOwn}
	switch token {
	case "me-fresh":
		return user(mfaUser, own, []string{"pwd"}, fresh), nil
	case "me-fresh-fed":
		return user(mfaUser, own, []string{"fed"}, fresh), nil
	case "me-stale":
		return user(mfaUser, own, []string{"pwd"}, stale), nil
	case "me-no-auth-time":
		return user(mfaUser, own, []string{"pwd"}, time.Time{}), nil
	case "me-acting":
		return auth.Principal{
			ID: mfaUser, Type: auth.PrincipalUser, Scopes: own, Audience: "identity", AuthTime: fresh,
			Act: &auth.Actor{ID: "agent", Type: auth.PrincipalAgent},
		}, nil
	case "me-api":
		return auth.Principal{ID: mfaUser, Type: auth.PrincipalUser, Scopes: own, Audience: "identity", TokenType: auth.TokenTypeAPI}, nil
	case "me-noscope":
		return user(mfaUser, []string{scopeUserRd}, []string{"pwd"}, fresh), nil
	case "service":
		return auth.Principal{ID: "svc", Type: auth.PrincipalService, Scopes: own, Audience: "identity"}, nil
	case "admin-mfa":
		return user(mfaAdmin, []string{scopeLinkRm, scopeAdmin, scopeLinkRead}, []string{"pwd", "otp", "mfa"}, fresh), nil
	case "admin-nomfa":
		return user(mfaAdmin, []string{scopeLinkRm, scopeAdmin}, []string{"pwd"}, fresh), nil
	case "admin-stale":
		return user(mfaAdmin, []string{scopeLinkRm, scopeAdmin}, []string{"pwd", "otp", "mfa"}, stale), nil
	case "admin-noadmin":
		return user(mfaAdmin, []string{scopeLinkRm}, []string{"pwd", "otp", "mfa"}, fresh), nil
	case "reader-user-read":
		return user(mfaAdmin, []string{scopeUserRd}, []string{"pwd"}, fresh), nil
	case "reader":
		return user(mfaAdmin, []string{scopeLinkRead}, []string{"pwd"}, fresh), nil
	}
	return auth.Principal{}, auth.ErrInvalidToken
}

type linkRig struct {
	h      http.Handler
	links  *mock.IdentityLinks
	users  *mock.Users
	events *mock.Events
	sess   *mock.Sessions
	mfa    *mock.MFA
}

func newLinkRig(t *testing.T) *linkRig {
	t.Helper()
	users := mock.NewUsers()
	for id, email := range map[string]string{mfaUser: "u@example.com", mfaOther: "o@example.com", mfaAdmin: "a@example.com"} {
		users.Rows[id] = domain.User{ID: id, Email: email, Name: id, Status: domain.UserActive, PasswordHash: "hash"}
	}
	r := &linkRig{links: mock.NewIdentityLinks(), users: users, events: &mock.Events{}, sess: mock.NewSessions(), mfa: mock.NewMFA()}
	cmd := commands.NewIdentityLinks(commands.IdentityLinksDeps{
		Users: users, Links: r.links, Sessions: r.sess, APITokens: mock.NewAPITokens(users), MFA: r.mfa, Events: r.events, Tx: mock.Tx{},
		PasskeysOn: true, ProviderOn: func(p string) bool { return p == "google" || p == "microsoft" },
		Log: slog.New(slog.NewTextHandler(devNull{}, nil)), Now: func() time.Time { return mfaNow },
	})
	r.h = httpapi.New(httpapi.Deps{
		JWKS: queries.NewGetJWKS(fakeKeys{}), Discovery: queries.NewGetDiscovery("https://id.example.com"),
		Verifier: linkVerifier{}, Scopes: realScopes(t), IdentityLinks: cmd, Now: func() time.Time { return mfaNow },
	}).Handler()
	return r
}

func (r *linkRig) add(id, userID, provider string) {
	r.links.Rows[id] = domain.IdentityLink{
		ID: id, UserID: userID, Provider: provider, Subject: "SUBJECT-" + id, Email: "up-" + id + "@example.com", CreatedAt: mfaNow.Add(-time.Hour),
	}
}

func wantFresh(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != freshChallenge || codeOf(t, rec) != "reauthentication_required" {
		t.Fatalf("%s: status %d, challenge %q, body %s", what, rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("%s: content type %q", what, got)
	}
}

// I26: the fresh login rule of MeIdentityLinks_remove. A token of 6 minutes and
// a token with no auth_time get the 401 with the challenge of a fresh login. A
// token with act and an API token get the 403 user_token_required before it, as
// for the other operations of the user (U19 tests the check itself). The link
// stays after a refusal. The rule does not check mfa.
func TestIssue16_FreshLoginOfMeRemove(t *testing.T) {
	r := newLinkRig(t)
	r.add("l1", mfaUser, "google")
	for _, tok := range []string{"me-acting", "me-api"} {
		wantProblem(t, tok, call(r.h, http.MethodDelete, "/v1/me/identity-links/google", tok, ""), http.StatusForbidden, "user_token_required")
	}
	for _, tok := range []string{"me-stale", "me-no-auth-time"} {
		wantFresh(t, tok, call(r.h, http.MethodDelete, "/v1/me/identity-links/google", tok, ""))
	}
	if len(r.links.Rows) != 1 {
		t.Fatal("the link must stay after a 401")
	}
	// A 401 comes before a 404 and before a 409.
	wantFresh(t, "unknown provider with a stale token", call(r.h, http.MethodDelete, "/v1/me/identity-links/okta", "me-stale", ""))
	// A token with no mfa and a fresh login is good (the user has no second factor).
	if rec := call(r.h, http.MethodDelete, "/v1/me/identity-links/google", "me-fresh", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if len(r.links.Rows) != 0 {
		t.Fatal("the link must be gone")
	}
}

// I26, I31: the order of the checks of MeIdentityLinks_remove.
func TestIssue16_MeRemoveOrder(t *testing.T) {
	r := newLinkRig(t)
	path := "/v1/me/identity-links/google"
	if rec := call(r.h, http.MethodDelete, path, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	wantProblem(t, "no scope", call(r.h, http.MethodDelete, path, "me-noscope", ""), http.StatusForbidden, "insufficient_scope")
	wantProblem(t, "service token", call(r.h, http.MethodDelete, path, "service", ""), http.StatusForbidden, "user_token_required")
	wantProblem(t, "no link", call(r.h, http.MethodDelete, path, "me-fresh", ""), http.StatusNotFound, "identity_link_not_found")
	for _, p := range []string{"okta", "Google", "microsoft"} {
		wantProblem(t, p, call(r.h, http.MethodDelete, "/v1/me/identity-links/"+p, "me-fresh", ""), http.StatusNotFound, "identity_link_not_found")
	}
	// The only login method is the link.
	u := r.users.Rows[mfaUser]
	u.PasswordHash = ""
	r.users.Rows[mfaUser] = u
	r.add("l1", mfaUser, "google")
	wantProblem(t, "last method", call(r.h, http.MethodDelete, path, "me-fresh", ""), http.StatusConflict, "last_login_method")
	// A second link, but no local factor: the removal is refused (P23).
	r.add("l2", mfaUser, "microsoft")
	wantFresh(t, "no local factor", call(r.h, http.MethodDelete, path, "me-fresh", ""))
	// A user with a TOTP factor has a local factor. A token of a login with only
	// an upstream account does not show one, so it is refused. A token with pwd
	// is good.
	r.mfa.TOTP[mfaUser] = domain.TOTPRecord{}
	wantFresh(t, "fed token", call(r.h, http.MethodDelete, path, "me-fresh-fed", ""))
	if len(r.links.Rows) != 2 {
		t.Fatal("a refusal changes nothing")
	}
	if rec := call(r.h, http.MethodDelete, path, "me-fresh", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("with a local factor: %d %s", rec.Code, rec.Body)
	}
	if len(r.links.Rows) != 1 || len(r.events.Audits) != 1 {
		t.Fatal("the removal writes one audit entry, and the refusals none")
	}
}

// I16, I28, I31: the admin operations. The list needs identity:identity_link:read,
// not identity:user:read. The removal needs the key, identity:admin, and a fresh
// MFA login.
func TestIssue16_AdminOperations(t *testing.T) {
	r := newLinkRig(t)
	r.add("l1", mfaOther, "google")
	list := "/v1/users/" + mfaOther + "/identity-links"
	wantProblem(t, "list with user:read", call(r.h, http.MethodGet, list, "reader-user-read", ""), http.StatusForbidden, "insufficient_scope")
	rec := call(r.h, http.MethodGet, list, "reader", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var page struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Items) != 1 {
		t.Fatalf("page = %s", rec.Body)
	}
	item := page.Items[0]
	if item["provider"] != "google" || item["email"] != "up-l1@example.com" || item["createdAt"] == nil {
		t.Fatalf("item = %v", item)
	}
	if _, has := item["subject"]; has || strings.Contains(rec.Body.String(), "SUBJECT-") {
		t.Fatalf("the list must not show the subject: %s", rec.Body)
	}
	wantProblem(t, "unknown user", call(r.h, http.MethodGet, "/v1/users/"+mfaUnknown+"/identity-links", "reader", ""), http.StatusNotFound, "user_not_found")
	wantProblem(t, "not a UUID", call(r.h, http.MethodGet, "/v1/users/abc/identity-links", "reader", ""), http.StatusNotFound, "user_not_found")

	rm := "/v1/users/" + mfaOther + "/identity-links/google"
	wantProblem(t, "no admin", call(r.h, http.MethodDelete, rm, "admin-noadmin", ""), http.StatusForbidden, "insufficient_scope")
	wantProblem(t, "user:read only", call(r.h, http.MethodDelete, rm, "reader-user-read", ""), http.StatusForbidden, "insufficient_scope")
	for _, tok := range []string{"admin-nomfa", "admin-stale"} {
		wantReauth(t, tok, call(r.h, http.MethodDelete, rm, tok, ""))
	}
	// 401 comes before 404.
	wantReauth(t, "stale and unknown user", call(r.h, http.MethodDelete, "/v1/users/"+mfaUnknown+"/identity-links/okta", "admin-nomfa", ""))
	wantProblem(t, "unknown user", call(r.h, http.MethodDelete, "/v1/users/"+mfaUnknown+"/identity-links/okta", "admin-mfa", ""), http.StatusNotFound, "user_not_found")
	wantProblem(t, "not a UUID", call(r.h, http.MethodDelete, "/v1/users/abc/identity-links/google", "admin-mfa", ""), http.StatusNotFound, "user_not_found")
	wantProblem(t, "unknown provider", call(r.h, http.MethodDelete, "/v1/users/"+mfaOther+"/identity-links/okta", "admin-mfa", ""), http.StatusNotFound, "identity_link_not_found")
	wantProblem(t, "no link", call(r.h, http.MethodDelete, "/v1/users/"+mfaOther+"/identity-links/microsoft", "admin-mfa", ""), http.StatusNotFound, "identity_link_not_found")
	if len(r.links.Rows) != 1 {
		t.Fatal("the link must stay")
	}
	if rec := call(r.h, http.MethodDelete, rm, "admin-mfa", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if len(r.links.Rows) != 0 || len(r.events.Audits) != 1 || r.events.Audits[0].Actor != mfaAdmin || r.events.Audits[0].TargetUserID != mfaOther {
		t.Fatalf("audits = %+v", r.events.Audits)
	}
	// The own account: the same rules.
	r.add("l2", mfaAdmin, "microsoft")
	u := r.users.Rows[mfaAdmin]
	u.PasswordHash = ""
	r.users.Rows[mfaAdmin] = u
	wantProblem(t, "own last method", call(r.h, http.MethodDelete, "/v1/users/"+mfaAdmin+"/identity-links/microsoft", "admin-mfa", ""), http.StatusConflict, "last_login_method")
}

// The list of the own links: the page and the user token rule.
func TestIssue16_MeList(t *testing.T) {
	r := newLinkRig(t)
	r.add("l1", mfaUser, "google")
	r.add("l2", mfaUser, "microsoft")
	rec := call(r.h, http.MethodGet, "/v1/me/identity-links?pageSize=1", "me-fresh", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var page struct {
		Items         []map[string]any `json:"items"`
		NextPageToken string           `json:"nextPageToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.NextPageToken == "" || page.Items[0]["provider"] != "google" {
		t.Fatalf("page = %s", rec.Body)
	}
	wantProblem(t, "service token", call(r.h, http.MethodGet, "/v1/me/identity-links", "service", ""), http.StatusForbidden, "user_token_required")
	wantProblem(t, "bad page size", call(r.h, http.MethodGet, "/v1/me/identity-links?pageSize=0", "me-fresh", ""), http.StatusBadRequest, "invalid_request")
}
