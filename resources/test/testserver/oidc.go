package testserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Clock is a clock that a test moves. A server uses it with WithClock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock makes a clock at the current time.
func NewClock() *Clock { return &Clock{t: time.Now().UTC()} }

// Now returns the time of the clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// PKCE is a code verifier and its S256 code challenge.
type PKCE struct{ Verifier, Challenge string }

// NewPKCE makes a code verifier of 43 characters from a random source.
func NewPKCE(t testing.TB) PKCE {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("testserver: random: %v", err)
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(v))
	return PKCE{Verifier: v, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}
}

// Random returns a random URL-safe value.
func Random(t testing.TB) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("testserver: random: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// AuthorizeQuery makes the query of an authorization request. extra replaces
// or adds values. An empty value removes the parameter.
func AuthorizeQuery(clientID, redirectURI, scope string, p PKCE, extra map[string]string) url.Values {
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {scope},
		"state": {"state-1"}, "nonce": {"nonce-1"}, "code_challenge": {p.Challenge}, "code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q
}

// Location returns the Location header as a URL.
func Location(t testing.TB, resp Response) *url.URL {
	t.Helper()
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("testserver: parse Location: %v", err)
	}
	return u
}

// Authorize sends GET /oauth/authorize.
func (w *Web) Authorize(t testing.TB, q url.Values) Response {
	t.Helper()
	resp, _ := w.Get(t, "/oauth/authorize?"+q.Encode())
	return resp
}

// CodeFlow does the browser part of the code flow with a login. It returns the
// redirect URL after the continue step, and the auth request ID. The browser
// must have no session, or it logs in again.
func (w *Web) CodeFlow(t testing.TB, q url.Values, email, password string) *url.URL {
	t.Helper()
	resp := w.Authorize(t, q)
	loc := Location(t, resp)
	if !strings.HasPrefix(loc.Path, "/login") {
		return loc
	}
	id := loc.Query().Get("authRequest")
	resp, _ = w.PostForm(t, "/login", url.Values{"email": {email}, "password": {password}, "authRequest": {id}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("testserver: login status = %d", resp.StatusCode)
	}
	resp, _ = w.Get(t, resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("testserver: continue status = %d", resp.StatusCode)
	}
	return Location(t, resp)
}

// TokenResponse is the body of a token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
}

// TokenRequest sends a form to the token endpoint and decodes the body.
func (s *Server) TokenRequest(t testing.TB, form url.Values) (Response, TokenResponse) {
	t.Helper()
	resp, b := s.PostToken(t, form)
	var tr TokenResponse
	_ = json.Unmarshal(b, &tr)
	return resp, tr
}

// CodeForm makes the form of an authorization_code token request.
func CodeForm(clientID, code, redirectURI, verifier string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}
}

// RefreshForm makes the form of a refresh_token token request.
func RefreshForm(clientID, refreshToken string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refreshToken}}
}

// JWTClaims returns the header and the claims of a JWT without a check.
func JWTClaims(t testing.TB, token string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("testserver: not a JWT: %q", token)
	}
	dec := func(s string) map[string]any {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("testserver: decode: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("testserver: decode JSON: %v", err)
		}
		return m
	}
	return dec(parts[0]), dec(parts[1])
}
