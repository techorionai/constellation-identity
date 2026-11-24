package testserver

import (
	"encoding/json"
	"net/url"
	"testing"
)

// IntrospectForm returns the form of an introspection request with a client
// assertion.
func IntrospectForm(assertion, token string) url.Values {
	return url.Values{
		"token":                 {token},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
}

// PostIntrospect sends an introspection request with a form.
func (s *Server) PostIntrospect(t testing.TB, form url.Values) (Response, map[string]any) {
	t.Helper()
	resp, b := s.Post(t, "/oauth/introspect", form.Encode())
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp, m
}

// Introspect asks the server about a token as the service client does.
func (s *Server) Introspect(t testing.TB, c ServiceClient, token string) (Response, map[string]any) {
	t.Helper()
	return s.PostIntrospect(t, IntrospectForm(s.Assertion(t, c, nil), token))
}

// CreateAPIToken calls MeApiTokens_create with the access token of a user. A
// value of days that is 0 leaves expiresInDays out.
func (s *Server) CreateAPIToken(t testing.TB, accessToken, name, scope string, days int) (Response, map[string]any) {
	t.Helper()
	body := map[string]any{"name": name, "scope": scope}
	if days != 0 {
		body["expiresInDays"] = days
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("testserver: encode body: %v", err)
	}
	resp, raw := s.Do(t, "POST", "/v1/me/api-tokens", accessToken, string(b))
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp, m
}

// APITokenOf returns the token value of a create response, or fails the test.
func APITokenOf(t testing.TB, m map[string]any) string {
	t.Helper()
	v, ok := m["token"].(string)
	if !ok || v == "" {
		t.Fatalf("testserver: the response has no token: %v", m)
	}
	return v
}
