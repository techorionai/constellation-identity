package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/techorionai/constellation-platform-go/executor"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	httpapi "github.com/techorionai/constellation-identity/internal/handlers/http"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

func withAuth(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func protectedServer(t *testing.T, scopes ...string) http.Handler {
	t.Helper()
	return httpapi.New(httpapi.Deps{
		JWKS:      queries.NewGetJWKS(fakeKeys{}),
		Discovery: queries.NewGetDiscovery("https://id.example.com"),
		Verifier:  allScopes{scopes: scopes},
		Scopes:    realScopes(t),
		Admin:     commands.NewAdmin(commands.AdminDeps{Clients: noClients{}, Users: noUsers{}}),
	}).Handler()
}

// noClients is a client repository with no client.
type noClients struct{ clients.Repository }

func (noClients) Get(context.Context, string) (domain.Client, error) {
	return domain.Client{}, clients.ErrNotFound
}

// noUsers is a user repository with no user.
type noUsers struct{ users.Repository }

func (noUsers) GetByID(context.Context, string) (domain.User, error) {
	return domain.User{}, users.ErrNotFound
}

// Issue2_U12: an operation with no x-required-scopes stops the start. The error
// names the operation.
func TestIssue2_U12_ScopeTableFailsClosed(t *testing.T) {
	spec := `
paths:
  /v1/roles:
    get:
      operationId: Roles_list
  /v1/me:
    get:
      operationId: Me_get
      x-required-scopes: []
`
	_, err := httpapi.NewScopeTable([]byte(spec))
	if err == nil || !strings.Contains(err.Error(), "Roles_list") {
		t.Fatalf("error = %v, want one that names Roles_list", err)
	}

	empty := `
paths:
  /v1/roles:
    get:
      operationId: Roles_list
      x-required-scopes: []
`
	if _, err := httpapi.NewScopeTable([]byte(empty)); err == nil || !strings.Contains(err.Error(), "Roles_list") {
		t.Fatalf("an empty list for Roles_list: %v", err)
	}
}

// Issue2_U12a: the real spec has an entry for each /v1 operation, and only
// Me_get has an empty list.
func TestIssue2_U12a_RealScopeTable(t *testing.T) {
	table := realScopes(t)
	if len(table) < 20 {
		t.Fatalf("entries = %d", len(table))
	}
	var empty []string
	for pattern, scopes := range table {
		if !strings.Contains(pattern, " /v1/") {
			t.Errorf("pattern %q", pattern)
		}
		if len(scopes) == 0 {
			empty = append(empty, pattern)
		}
	}
	if !slices.Equal(empty, []string{"GET /v1/me"}) {
		t.Fatalf("empty lists = %v", empty)
	}
	if got := table["PUT /v1/permission-manifests/{app}"]; !slices.Equal(got, []string{"identity:manifest:publish"}) {
		t.Fatalf("publish scopes = %v", got)
	}
	if got := table["POST /v1/clients"]; !slices.Equal(got, []string{"identity:client:write", "identity:admin"}) {
		t.Fatalf("client create scopes = %v", got)
	}
}

// Issue2_U12b: a list of two scopes needs both.
func TestIssue2_U12b_BothScopes(t *testing.T) {
	// This route needs identity:client:write and identity:admin.
	const path = "/v1/clients/helpdesk/keys/k1"
	h := protectedServer(t, "identity:client:write")
	rec := withAuth(h, http.MethodDelete, path, "ok")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	var p struct {
		Code          string   `json:"code"`
		MissingScopes []string `json:"missingScopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.MissingScopes, []string{"identity:admin"}) {
		t.Fatalf("missingScopes = %v", p.MissingScopes)
	}
	h = protectedServer(t, "identity:client:write", "identity:admin")
	// The scope check passes. The client does not exist.
	if rec := withAuth(h, http.MethodDelete, path, "ok"); rec.Code != http.StatusNotFound {
		t.Fatalf("with both scopes: status = %d", rec.Code)
	}
}

func TestIssue2_ProtectedRoutes(t *testing.T) {
	h := protectedServer(t)
	if rec := withAuth(h, http.MethodGet, "/v1/roles", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d", rec.Code)
	}
	if rec := withAuth(h, http.MethodGet, "/v1/roles", "bad"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: status = %d", rec.Code)
	}
	// Me_get needs a token and no scope. The token of the test is the token of
	// a service, so the answer is 403.
	if rec := withAuth(h, http.MethodGet, "/v1/me", "ok"); rec.Code != http.StatusForbidden {
		t.Fatalf("/v1/me: status = %d", rec.Code)
	}
	// The public routes need no token.
	if rec := withAuth(h, http.MethodGet, "/.well-known/jwks.json", ""); rec.Code != http.StatusOK {
		t.Fatalf("jwks: status = %d", rec.Code)
	}
}

// A /v1 route with no entry in the table, or a server with no verifier, fails
// closed.
func TestIssue2_NoTableEntryFailsClosed(t *testing.T) {
	noTable := httpapi.New(httpapi.Deps{Verifier: allScopes{}}).Handler()
	if rec := withAuth(noTable, http.MethodGet, "/v1/me", "ok"); rec.Code != http.StatusInternalServerError {
		t.Fatalf("no table: status = %d", rec.Code)
	}
	noVerifier := httpapi.New(httpapi.Deps{Scopes: realScopes(t)}).Handler()
	if rec := withAuth(noVerifier, http.MethodGet, "/v1/me", "ok"); rec.Code != http.StatusInternalServerError {
		t.Fatalf("no verifier: status = %d", rec.Code)
	}
}

// The two operations that the pages router serves answer 501 with a Problem
// body, if a request reaches the generated server.
func TestNotImplementedOperations(t *testing.T) {
	rec := get(newServer("https://id.example.com"), http.MethodGet, "/oauth/end_session", "")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("end_session: status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	var p map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p["code"] != "not_implemented" || p["status"] != float64(501) {
		t.Fatalf("problem = %v", p)
	}
}

func tokenServer(exec func(commands.IssueServiceToken) (commands.IssueServiceTokenResult, error)) http.Handler {
	return httpapi.New(httpapi.Deps{
		IssueToken: executor.FuncWithReturn[commands.IssueServiceToken, commands.IssueServiceTokenResult](
			func(_ context.Context, in commands.IssueServiceToken) (commands.IssueServiceTokenResult, error) {
				return exec(in)
			}),
	}).Handler()
}

func TestIssue2_TokenEndpointResponses(t *testing.T) {
	var seen commands.IssueServiceToken
	h := tokenServer(func(in commands.IssueServiceToken) (commands.IssueServiceTokenResult, error) {
		seen = in
		return commands.IssueServiceTokenResult{AccessToken: "tok", ExpiresIn: 300, Scope: "demo:ticket:read"}, nil
	})
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_assertion_type": {domain.AssertionType},
		"client_assertion": {"a.b.c"}, "audience": {"demo"}, "scope": {"demo:ticket:read"}, "client_id": {"helpdesk"},
	}
	rec := get(h, http.MethodPost, "/oauth/token", form.Encode())
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("status %d, headers %v", rec.Code, rec.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["access_token"] != "tok" || body["token_type"] != "Bearer" || body["expires_in"] != float64(300) || body["scope"] != "demo:ticket:read" {
		t.Fatalf("body = %v", body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatal("the response has a refresh token")
	}
	if seen.Assertion != "a.b.c" || seen.Audience != "demo" || seen.ClientID != "helpdesk" || seen.SecondAuthentication || seen.RepeatedParameter {
		t.Fatalf("command input = %+v", seen)
	}

	// A client secret, and a repeated parameter.
	get(h, http.MethodPost, "/oauth/token", form.Encode()+"&client_secret=x")
	if !seen.SecondAuthentication {
		t.Fatalf("client_secret was not seen: %+v", seen)
	}
	get(h, http.MethodPost, "/oauth/token", form.Encode()+"&audience=other")
	if !seen.RepeatedParameter {
		t.Fatalf("a repeated parameter was not seen: %+v", seen)
	}
}

// The service rejects an Authorization header with the scheme Basic only. A
// header with another scheme does not change the result.
func TestIssue2_U12e_AuthorizationHeaderScheme(t *testing.T) {
	var seen commands.IssueServiceToken
	h := tokenServer(func(in commands.IssueServiceToken) (commands.IssueServiceTokenResult, error) {
		seen = in
		return commands.IssueServiceTokenResult{AccessToken: "tok", ExpiresIn: 300, Scope: "demo:ticket:read"}, nil
	})
	body := url.Values{
		"grant_type": {"client_credentials"}, "client_assertion_type": {domain.AssertionType},
		"client_assertion": {"a.b.c"}, "audience": {"demo"}, "scope": {"demo:ticket:read"},
	}.Encode()
	for header, want := range map[string]bool{
		"Basic dTpw": true, "basic dTpw": true, "Bearer x": false, "Negotiate x": false, "": false,
	} {
		seen = commands.IssueServiceToken{}
		req := httptest.NewRequestWithContext(t0(), http.MethodPost, "/oauth/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		if seen.SecondAuthentication != want {
			t.Errorf("Authorization %q: SecondAuthentication = %v, want %v", header, seen.SecondAuthentication, want)
		}
	}
}

func TestIssue2_TokenEndpointErrors(t *testing.T) {
	for code, status := range map[string]int{
		"invalid_request": 400, "invalid_client": 401, "unauthorized_client": 400, "invalid_scope": 400,
		"invalid_target": 400, "unsupported_grant_type": 400, "server_error": 500, "temporarily_unavailable": 503,
	} {
		h := tokenServer(func(commands.IssueServiceToken) (commands.IssueServiceTokenResult, error) {
			return commands.IssueServiceTokenResult{}, apperrors.NewOAuthError(code, "text", nil)
		})
		rec := get(h, http.MethodPost, "/oauth/token", "grant_type=client_credentials")
		if rec.Code != status {
			t.Errorf("%s: status = %d, want %d", code, rec.Code, status)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != code {
			t.Errorf("%s: body = %s", code, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control = %q", code, rec.Header().Get("Cache-Control"))
		}
	}
}

func TestIssue2_ValidationProblem(t *testing.T) {
	h := httpapi.New(httpapi.Deps{
		Verifier: allScopes{scopes: []string{"identity:manifest:publish"}},
		Scopes:   realScopes(t),
		PublishManifest: executor.FuncWithReturn[commands.PublishManifest, domain.PublishedManifest](
			func(context.Context, commands.PublishManifest) (domain.PublishedManifest, error) {
				return domain.PublishedManifest{}, apperrors.NewValidationError([]domain.FieldError{
					{Code: "permission_app_mismatch", Field: "/permissions/0/key", Message: "m"},
					{Code: "duplicate_key", Field: "/defaultRoles/1/key", Message: "m"},
				})
			}),
	}).Handler()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/v1/permission-manifests/demo",
		strings.NewReader(`{"app":"demo","permissions":[],"defaultRoles":[]}`))
	req.Header.Set("Authorization", "Bearer ok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var p struct {
		Code   string `json:"code"`
		Errors []struct {
			Code  string `json:"code"`
			Field string `json:"field"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Code != "permission_app_mismatch" || len(p.Errors) != 2 || p.Errors[1].Field != "/defaultRoles/1/key" {
		t.Fatalf("problem = %+v", p)
	}
}
