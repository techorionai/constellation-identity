package httpapi_test

import (
	"context"
	"encoding/json"
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

const testUser = "11111111-1111-4111-8111-111111111111"

// tokenVerifier gives a principal for four test tokens. Any other value,
// also a cpat_ value, is not a JWT, so the verifier refuses it like the JWT
// verifier of the service does.
type tokenVerifier struct{}

func (tokenVerifier) Verify(_ context.Context, token string) (auth.Principal, error) {
	scopes := []string{"identity:api_token:manage_own"}
	switch token {
	case "user":
		return auth.Principal{ID: testUser, Type: auth.PrincipalUser, Scopes: scopes, Audience: "identity"}, nil
	case "service":
		return auth.Principal{ID: "svc", Type: auth.PrincipalService, Scopes: scopes, Audience: "identity"}, nil
	case "acting":
		return auth.Principal{ID: testUser, Type: auth.PrincipalUser, Scopes: scopes, Audience: "identity",
			Act: &auth.Actor{ID: "agent", Type: auth.PrincipalAgent}}, nil
	case "apitoken":
		return auth.Principal{ID: testUser, Type: auth.PrincipalUser, Scopes: scopes, Audience: "identity", TokenType: auth.TokenTypeAPI}, nil
	}
	return auth.Principal{}, auth.ErrInvalidToken
}

func apiTokenServer(t *testing.T) http.Handler {
	t.Helper()
	users := mock.NewUsers()
	users.Rows[testUser] = domain.User{ID: testUser, Email: "u@example.com", Name: "U", Status: domain.UserActive}
	roles := mock.NewUserRoles(users)
	roles.Perms[domain.UserRole] = []string{"identity:api_token:manage_own"}
	roles.Perms[domain.RoleRef{App: "helpdesk", Role: "agent"}] = []string{"helpdesk:ticket:read"}
	roles.Rows[testUser] = []domain.RoleRef{{App: "helpdesk", Role: "agent"}}
	cmd := commands.NewAPITokens(commands.APITokensDeps{
		Tokens: mock.NewAPITokens(users), Users: users, UserRoles: roles, Tx: mock.Tx{}, Now: time.Now,
		Settings: commands.APITokenSettings{DefaultTTLDays: 90, MaxTTLDays: 365, MaxPerUser: 5},
	})
	return httpapi.New(httpapi.Deps{
		JWKS: queries.NewGetJWKS(fakeKeys{}), Discovery: queries.NewGetDiscovery("https://id.example.com"),
		Verifier: tokenVerifier{}, Scopes: realScopes(t), APITokens: cmd,
	}).Handler()
}

func call(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func code(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return p.Code
}

const createBody = `{"name":"ci","scope":"helpdesk:ticket:read"}`

// Issue9_U12: a service token, a token with Act, and an API token that the
// verifier accepted give 403 user_token_required on the three self-service
// operations.
func TestIssue9_U12_UserTokenRequired(t *testing.T) {
	h := apiTokenServer(t)
	for _, token := range []string{"service", "acting", "apitoken"} {
		for _, op := range []struct{ method, path, body string }{
			{http.MethodGet, "/v1/me/api-tokens", ""},
			{http.MethodPost, "/v1/me/api-tokens", createBody},
			{http.MethodDelete, "/v1/me/api-tokens/33333333-3333-4333-8333-333333333333", ""},
		} {
			rec := call(h, op.method, op.path, token, op.body)
			if rec.Code != http.StatusForbidden || code(t, rec) != "user_token_required" {
				t.Errorf("%s %s with %s: status %d, body %s", op.method, op.path, token, rec.Code, rec.Body)
			}
		}
	}
}

// Issue9_U12a: a cpat_ value as the bearer token on /v1 gives 401. The handler
// does not run.
func TestIssue9_U12a_APITokenOnV1(t *testing.T) {
	h := apiTokenServer(t)
	created := call(h, http.MethodPost, "/v1/me/api-tokens", "user", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", created.Code, created.Body)
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &body); err != nil || !strings.HasPrefix(body.Token, "cpat_") {
		t.Fatalf("token = %q, %v", body.Token, err)
	}
	rec := call(h, http.MethodGet, "/v1/me/api-tokens", body.Token, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
}

// Issue9_U3 (not an integer): a value of expiresInDays that is not an integer
// gives 400 invalid_request. A bad name gives 400 too.
func TestIssue9_U3_NotAnInteger(t *testing.T) {
	h := apiTokenServer(t)
	for _, body := range []string{
		`{"name":"ci","scope":"helpdesk:ticket:read","expiresInDays":1.5}`,
		`{"name":"ci","scope":"helpdesk:ticket:read","expiresInDays":"7"}`,
		`{"name":"ci","scope":"helpdesk:ticket:read","expiresInDays":0}`,
		`{"name":"ci","scope":"helpdesk:ticket:read","expiresInDays":366}`,
		`{"name":"","scope":"helpdesk:ticket:read"}`,
	} {
		rec := call(h, http.MethodPost, "/v1/me/api-tokens", "user", body)
		if rec.Code != http.StatusBadRequest || code(t, rec) != "invalid_request" {
			t.Errorf("body %s: status %d, body %s", body, rec.Code, rec.Body)
		}
	}
}

// Issue9_Create: the response of create has the token one time and the no-store
// headers. The list has no token value and no hash. The 422 answers have the
// field errors.
func TestIssue9_CreateListRevoke(t *testing.T) {
	h := apiTokenServer(t)
	rec := call(h, http.MethodPost, "/v1/me/api-tokens", "user", createBody)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("create: status %d, headers %v", rec.Code, rec.Header())
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	list := call(h, http.MethodGet, "/v1/me/api-tokens", "user", "")
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), created.Token) || strings.Contains(list.Body.String(), domain.HashSecret(created.Token)) ||
		!strings.Contains(list.Body.String(), created.ID) || strings.Contains(list.Body.String(), `"token"`) {
		t.Fatalf("list: status %d, body %s", list.Code, list.Body)
	}
	bad := call(h, http.MethodPost, "/v1/me/api-tokens", "user", `{"name":"x","scope":"billing:invoice:read"}`)
	if bad.Code != http.StatusUnprocessableEntity || code(t, bad) != "scope_not_granted" || !strings.Contains(bad.Body.String(), `"/scope"`) {
		t.Fatalf("scope: status %d, body %s", bad.Code, bad.Body)
	}
	if rev := call(h, http.MethodDelete, "/v1/me/api-tokens/"+created.ID, "user", ""); rev.Code != http.StatusNoContent {
		t.Fatalf("revoke: status %d, body %s", rev.Code, rev.Body)
	}
	miss := call(h, http.MethodDelete, "/v1/me/api-tokens/not-a-uuid", "user", "")
	if miss.Code != http.StatusNotFound || code(t, miss) != "api_token_not_found" {
		t.Fatalf("bad ID: status %d, body %s", miss.Code, miss.Body)
	}
}

// Issue9_U15: the discovery document has introspection_endpoint.
func TestIssue9_U15_DiscoveryIntrospection(t *testing.T) {
	rec := get(newServer("https://id.example.com"), http.MethodGet, "/.well-known/openid-configuration", "")
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["introspection_endpoint"] != "https://id.example.com/oauth/introspect" {
		t.Fatalf("introspection_endpoint = %v", doc["introspection_endpoint"])
	}
	if l, ok := doc["grant_types_supported"].([]any); !ok || len(l) != 4 {
		t.Fatalf("grant_types_supported = %v", doc["grant_types_supported"])
	}
}
