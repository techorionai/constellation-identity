// Package oidcprovider is a test OIDC provider. It is a real HTTP server on a
// random port with a discovery document, a key set, an authorization endpoint,
// and a token endpoint. It signs ID tokens with its own key and makes the claim
// sets of Google and of Microsoft. The service calls it over HTTP in the same
// way as a real provider. Import it from test code only.
//
// The discovery documents are copies of the real documents (see testdata). Only
// the hosts are different.
package oidcprovider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

//go:embed testdata/google.json testdata/microsoft.json
var fixtures embed.FS

// The values that the provider expects, until a test changes them.
const (
	GoogleClientID = "google-client-id"
	GoogleSecret   = "google-client-secret"
	MSClientID     = "microsoft-client-id"
	MSSecret       = "microsoft-client-secret"
	// TenantA and TenantB are two tenant GUIDs.
	TenantA = "11111111-aaaa-4aaa-8aaa-111111111111"
	TenantB = "22222222-bbbb-4bbb-8bbb-222222222222"
)

// The kinds of signing key of Microsoft. The JWKS has four keys with the same
// key material and with different issuer properties.
const (
	// KeyTemplate has the issuer property with the text {tenantid}.
	KeyTemplate = "template"
	// KeyTenantA and KeyTenantB have a GUID issuer.
	KeyTenantA = "tenant-a"
	KeyTenantB = "tenant-b"
	// KeyNone has no issuer property.
	KeyNone = "none"
)

// Login is the identity that the next authorization request logs in, and the
// changes that a test makes to the ID token.
type Login struct {
	// Provider is "google" or "microsoft".
	Provider string
	// Sub is the subject of Google. Oid and Tid are for Microsoft.
	Sub, Oid, Tid string
	Email         string
	// EmailVerified is the claim email_verified of Google. The default is true.
	// A test can set false, "true", or nil with OmitEmailVerified.
	EmailVerified     any
	OmitEmailVerified bool
	// XmsEdov is the optional claim of Microsoft. A test sets it for a verified
	// email. Nil means the claim is absent.
	XmsEdov any
	// HD is the hosted domain of Google.
	HD string
	// AuthTime is the time of the session of the user at the provider. A zero value
	// means the token has no auth_time (and the iat is the time of the request).
	AuthTime time.Time
	// IssuedAt replaces iat if it is not zero.
	IssuedAt time.Time

	// Changes of the token. A zero value means no change.
	Aud     []string
	Azp     *string
	Nonce   *string
	Iss     string
	Expired bool
	// KeyKind is the signing key of Microsoft. The default is KeyTemplate.
	KeyKind string
	// IssParam is the iss parameter of the redirect of Google. The default is the
	// issuer. OmitIss removes the parameter.
	IssParam string
	OmitIss  bool
	// NoUserStep makes the provider ignore prompt=login, as a provider that has
	// no forced login (Google) does.
	NoUserStep bool
	// AuthError makes the authorization endpoint answer with this error code.
	AuthError string
	// TokenError makes the token endpoint answer with this OAuth error code.
	TokenError string
}

// AuthRequest is the record of an authorization request.
type AuthRequest struct {
	Provider string
	Query    url.Values
	// UserStep is true when the request made the provider ask the user to log in
	// again (prompt=login at Microsoft).
	UserStep bool
}

// Provider is a test provider.
type Provider struct {
	// URL is the base URL of the server.
	URL    string
	server *httptest.Server
	key    *rsa.PrivateKey

	// Clock is the clock of the provider. The default is time.Now. A test that
	// moves the clock of the service sets the same clock here.
	Clock func() time.Time

	mu       sync.Mutex
	next     *Login
	codes    map[string]*grant
	secrets  map[string]string
	delays   map[string]time.Duration
	requests []AuthRequest
	hosts    []string
}

type grant struct {
	login       Login
	clientID    string
	redirectURI string
	challenge   string
	nonce       string
	provider    string
	userStep    bool
}

// Start starts a provider. It stops at the end of the test.
func Start(t testing.TB) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidcprovider: key: %v", err)
	}
	p := &Provider{
		key: key, codes: map[string]*grant{},
		secrets: map[string]string{"google": GoogleSecret, "microsoft": MSSecret},
		delays:  map[string]time.Duration{},
	}
	mux := http.NewServeMux()
	// Google.
	mux.HandleFunc("GET /google/.well-known/openid-configuration", p.discoveryGoogle)
	mux.HandleFunc("GET /google/o/oauth2/v2/auth", func(w http.ResponseWriter, r *http.Request) { p.authorize(w, r, "google") })
	mux.HandleFunc("POST /google/oauth2googleapis/token", func(w http.ResponseWriter, r *http.Request) { p.token(w, r, "google") })
	mux.HandleFunc("GET /google/wwwgoogleapis/oauth2/v3/certs", func(w http.ResponseWriter, r *http.Request) { p.jwks(w, r, "google") })
	// Microsoft. {tenant} is "organizations" or a GUID.
	mux.HandleFunc("GET /ms/organizations/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		p.discoveryMicrosoft(w, r, "organizations")
	})
	mux.HandleFunc("GET /ms/{tenant}/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		p.discoveryMicrosoft(w, r, r.PathValue("tenant"))
	})
	mux.HandleFunc("GET /ms/{tenant}/oauth2/v2.0/authorize", func(w http.ResponseWriter, r *http.Request) { p.authorize(w, r, "microsoft") })
	mux.HandleFunc("POST /ms/{tenant}/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) { p.token(w, r, "microsoft") })
	mux.HandleFunc("GET /ms/{tenant}/discovery/v2.0/keys", func(w http.ResponseWriter, r *http.Request) { p.jwks(w, r, "microsoft") })
	p.server = httptest.NewServer(mux)
	p.URL = p.server.URL
	t.Cleanup(p.server.Close)
	return p
}

func (p *Provider) now() time.Time {
	if p.Clock != nil {
		return p.Clock()
	}
	return time.Now()
}

// GoogleBase returns the issuer of the Google side.
func (p *Provider) GoogleBase() string { return p.URL + "/google" }

// MicrosoftBase returns the login base of the Microsoft side.
func (p *Provider) MicrosoftBase() string { return p.URL + "/ms" }

// Host returns the host and the port of the server.
func (p *Provider) Host() string { return strings.TrimPrefix(p.URL, "http://") }

// Expect sets the identity of the next authorization request.
func (p *Provider) Expect(l Login) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next = &l
}

// SetSecret changes the client secret that the token endpoint expects.
func (p *Provider) SetSecret(provider, secret string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.secrets[provider] = secret
}

// SetDelay makes the endpoint wait before it answers. The names are
// "discovery", "authorize", "token", and "keys".
func (p *Provider) SetDelay(endpoint string, d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.delays[endpoint] = d
}

// AuthRequests returns the authorization requests that the provider got.
func (p *Provider) AuthRequests() []AuthRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]AuthRequest(nil), p.requests...)
}

// LastAuthRequest returns the last authorization request.
func (p *Provider) LastAuthRequest(t testing.TB) AuthRequest {
	t.Helper()
	r := p.AuthRequests()
	if len(r) == 0 {
		t.Fatal("oidcprovider: no authorization request")
	}
	return r[len(r)-1]
}

// Hosts returns the Host header of each request that the provider got. A test
// uses it to check that the service calls the test provider only.
func (p *Provider) Hosts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.hosts...)
}

func (p *Provider) wait(r *http.Request, endpoint string) bool {
	p.mu.Lock()
	d := p.delays[endpoint]
	p.hosts = append(p.hosts, r.Host)
	p.mu.Unlock()
	if d <= 0 {
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-r.Context().Done():
		return false
	}
}

func (p *Provider) fixture(name string) string {
	b, err := fixtures.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return strings.ReplaceAll(string(b), "{BASE}", p.URL)
}

func (p *Provider) discoveryGoogle(w http.ResponseWriter, r *http.Request) {
	if !p.wait(r, "discovery") {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(p.fixture("google.json")))
}

// discoveryMicrosoft serves the document of "organizations" with the text
// {tenantid} in the issuer, as the real document has. For a tenant GUID it
// replaces the text and the tenant in the paths.
func (p *Provider) discoveryMicrosoft(w http.ResponseWriter, r *http.Request, tenant string) {
	if !p.wait(r, "discovery") {
		return
	}
	doc := p.fixture("microsoft.json")
	if tenant != "organizations" {
		doc = strings.ReplaceAll(doc, "{tenantid}", tenant)
		doc = strings.ReplaceAll(doc, "/ms/organizations/", "/ms/"+tenant+"/")
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(doc)) //nolint:gosec // G705: the document is a fixture of the test provider.
}

const kid = "test-key"

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request, provider string) {
	if !p.wait(r, "keys") {
		return
	}
	pub := jose.JSONWebKey{Key: &p.key.PublicKey, Algorithm: "RS256", Use: "sig"}
	var keys []map[string]any
	add := func(id, issuer string) {
		k := pub
		k.KeyID = id
		raw, _ := k.MarshalJSON()
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if issuer != "" {
			m["issuer"] = issuer
		}
		keys = append(keys, m)
	}
	if provider == "google" {
		add(kid, "")
	} else {
		add(kid+"-"+KeyTemplate, p.MicrosoftBase()+"/{tenantid}/v2.0")
		add(kid+"-"+KeyTenantA, p.MicrosoftBase()+"/"+TenantA+"/v2.0")
		add(kid+"-"+KeyTenantB, p.MicrosoftBase()+"/"+TenantB+"/v2.0")
		add(kid+"-"+KeyNone, "")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func randomText() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// authorize is the authorization endpoint. It has no user step except for
// prompt=login at Microsoft. It redirects to the redirect URI with the code.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request, provider string) {
	if !p.wait(r, "authorize") {
		return
	}
	q := r.URL.Query()
	p.mu.Lock()
	login := p.next
	p.mu.Unlock()
	redirect := q.Get("redirect_uri")
	if q.Get("response_type") != "code" || q.Get("client_id") == "" || redirect == "" || q.Get("state") == "" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	userStep := provider == "microsoft" && q.Get("prompt") == "login" && (login == nil || !login.NoUserStep)
	p.mu.Lock()
	p.requests = append(p.requests, AuthRequest{Provider: provider, Query: q, UserStep: userStep})
	p.mu.Unlock()
	u, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	out := u.Query()
	out.Set("state", q.Get("state"))
	if login == nil || login.AuthError != "" {
		code := "access_denied"
		if login != nil {
			code = login.AuthError
		}
		out.Set("error", code)
		out.Set("error_description", "TEXT-FROM-THE-PROVIDER-"+randomText())
	} else {
		code := randomText()
		p.mu.Lock()
		p.codes[code] = &grant{
			login: *login, clientID: q.Get("client_id"), redirectURI: redirect, challenge: q.Get("code_challenge"),
			nonce: q.Get("nonce"), provider: provider, userStep: userStep,
		}
		p.mu.Unlock()
		out.Set("code", code)
		if provider == "google" && !login.OmitIss {
			iss := p.GoogleBase()
			if login.IssParam != "" {
				iss = login.IssParam
			}
			out.Set("iss", iss)
		}
	}
	u.RawQuery = out.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: the test provider redirects to the URI of the test.
}

// token is the token endpoint. It checks the client secret, the redirect URI,
// and the PKCE verifier (S256).
func (p *Provider) token(w http.ResponseWriter, r *http.Request, provider string) {
	if !p.wait(r, "token") {
		return
	}
	oauthError := func(status int, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	if err := r.ParseForm(); err != nil {
		oauthError(http.StatusBadRequest, "invalid_request")
		return
	}
	clientID, secret, ok := r.BasicAuth()
	if !ok {
		clientID, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	} else if u, err := url.QueryUnescape(clientID); err == nil {
		clientID = u
		secret, _ = url.QueryUnescape(secret)
	}
	p.mu.Lock()
	want := p.secrets[provider]
	g := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	if subtle.ConstantTimeCompare([]byte(secret), []byte(want)) != 1 {
		oauthError(http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" || g == nil || g.provider != provider {
		oauthError(http.StatusBadRequest, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if clientID != g.clientID || r.PostForm.Get("redirect_uri") != g.redirectURI ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge || g.login.TokenError != "" {
		code := "invalid_grant"
		if g.login.TokenError != "" {
			code = g.login.TokenError
		}
		oauthError(http.StatusBadRequest, code)
		return
	}
	idToken, err := p.sign(g)
	if err != nil {
		oauthError(http.StatusInternalServerError, "server_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "UPSTREAM-ACCESS-" + randomText(), "token_type": "Bearer", "expires_in": 3600,
		"id_token": idToken, "refresh_token": "UPSTREAM-REFRESH-" + randomText(),
	})
}

// sign makes the ID token of a grant.
func (p *Provider) sign(g *grant) (string, error) {
	l := g.login
	now := p.now()
	iat := now
	authTime := l.AuthTime
	if g.userStep {
		// The user logged in again at the provider.
		authTime = now
	}
	if !l.IssuedAt.IsZero() {
		iat = l.IssuedAt
	}
	exp := now.Add(time.Hour)
	if l.Expired {
		exp = now.Add(-time.Hour)
	}
	nonce := g.nonce
	if l.Nonce != nil {
		nonce = *l.Nonce
	}
	aud := []string{g.clientID}
	if len(l.Aud) > 0 {
		aud = l.Aud
	}
	claims := map[string]any{"aud": aud, "iat": iat.Unix(), "exp": exp.Unix(), "nonce": nonce}
	keyID := kid
	switch g.provider {
	case "google":
		claims["iss"] = p.GoogleBase()
		claims["azp"] = g.clientID
		claims["sub"] = l.Sub
		if l.Email != "" {
			claims["email"] = l.Email
		}
		if !l.OmitEmailVerified {
			if l.EmailVerified == nil {
				claims["email_verified"] = true
			} else {
				claims["email_verified"] = l.EmailVerified
			}
		}
		if l.HD != "" {
			claims["hd"] = l.HD
		}
		if !authTime.IsZero() {
			claims["auth_time"] = authTime.Unix()
		}
	default:
		tid := l.Tid
		if tid == "" {
			tid = TenantA
		}
		claims["iss"] = p.MicrosoftBase() + "/" + tid + "/v2.0"
		claims["tid"], claims["oid"], claims["sub"], claims["ver"] = tid, l.Oid, "pairwise-"+l.Oid, "2.0"
		if l.Email != "" {
			claims["email"] = l.Email
		}
		if l.XmsEdov != nil {
			claims["xms_edov"] = l.XmsEdov
		}
		if !authTime.IsZero() {
			claims["auth_time"] = authTime.Unix()
		}
		kind := l.KeyKind
		if kind == "" {
			kind = KeyTemplate
		}
		keyID = kid + "-" + kind
	}
	if l.Iss != "" {
		claims["iss"] = l.Iss
	}
	if l.Azp != nil {
		claims["azp"] = *l.Azp
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("signer: %w", err)
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}
