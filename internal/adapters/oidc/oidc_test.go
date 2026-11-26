package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	adapter "github.com/techorionai/constellation-identity/internal/adapters/oidc"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/upstreamidp"
	"github.com/techorionai/constellation-identity/resources/test/oidcprovider"
)

var bg = context.Background()

func newClient(t *testing.T, p *oidcprovider.Provider, tenant string, domains ...string) *adapter.Client {
	t.Helper()
	return adapter.New(adapter.Config{
		Issuer: "https://id.example.com", HTTPTimeout: 3 * time.Second, Transport: p.Transport(),
		Google: adapter.ProviderConfig{
			ClientID: oidcprovider.GoogleClientID, ClientSecret: oidcprovider.GoogleSecret, AllowedDomains: domains,
		},
		Microsoft: adapter.ProviderConfig{
			ClientID: oidcprovider.MSClientID, ClientSecret: oidcprovider.MSSecret, Tenant: tenant,
		},
	})
}

// authorize does the browser steps: the authorization request at the provider.
// It returns the code and the iss parameter of the redirect.
func authorize(t *testing.T, c *adapter.Client, pr *oidcprovider.Provider, provider string, p upstreamidp.AuthParams) (code, iss, errCode string) {
	t.Helper()
	loc, err := c.AuthCodeURL(bg, provider, p)
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	hc := &http.Client{Transport: pr.Transport(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(bg, http.MethodGet, loc, nil)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorization: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	q := u.Query()
	return q.Get("code"), q.Get("iss"), q.Get("error")
}

func params() upstreamidp.AuthParams {
	return upstreamidp.AuthParams{State: "state-1", Nonce: "nonce-1", Verifier: strings.Repeat("v", 43)}
}

// exchange runs the login of a provider with an identity and returns the result.
func exchange(t *testing.T, c *adapter.Client, p *oidcprovider.Provider, login oidcprovider.Login) (domain.UpstreamIdentity, error) {
	t.Helper()
	p.Expect(login)
	ap := params()
	code, iss, _ := authorize(t, c, p, login.Provider, ap)
	return c.Exchange(bg, login.Provider, upstreamidp.ExchangeParams{Code: code, Verifier: ap.Verifier, Nonce: ap.Nonce, Iss: iss})
}

func googleLogin(mod func(*oidcprovider.Login)) oidcprovider.Login {
	l := oidcprovider.Login{Provider: "google", Sub: "g-sub-1", Email: "user@example.com"}
	if mod != nil {
		mod(&l)
	}
	return l
}

func msLogin(mod func(*oidcprovider.Login)) oidcprovider.Login {
	l := oidcprovider.Login{Provider: "microsoft", Oid: "oid-1", Tid: oidcprovider.TenantA, Email: "user@example.com", XmsEdov: true}
	if mod != nil {
		mod(&l)
	}
	return l
}

// U10: the Google issuer with the normal go-oidc verifier. The text
// accounts.google.com with no scheme is accepted for Google only.
func TestIssue16_U10_GoogleIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	v := gooidc.NewVerifier(domain.GoogleIssuer, &gooidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &gooidc.Config{ClientID: "c"})
	for _, c := range []struct {
		iss string
		ok  bool
	}{{"https://accounts.google.com", true}, {"accounts.google.com", true}, {"https://evil.example.com", false}} {
		raw, err := jwt.Signed(signer).Claims(map[string]any{
			"iss": c.iss, "aud": "c", "sub": "s", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(bg, raw); (err == nil) != c.ok {
			t.Errorf("issuer %q: err = %v, want ok %v", c.iss, err, c.ok)
		}
	}
}

// U13: the authorization URL for Microsoft with the real discovery document of
// organizations. The document has no code_challenge_methods_supported, and the
// adapter always sends an S256 challenge.
func TestIssue16_U13_MicrosoftAuthURL(t *testing.T) {
	p := oidcprovider.Start(t)
	c := newClient(t, p, "organizations")
	loc, err := c.AuthCodeURL(bg, "microsoft", params())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(loc)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("response_type") != "code" ||
		q.Get("response_mode") != "query" || q.Get("scope") != "openid email profile" || q.Get("state") != "state-1" ||
		q.Get("nonce") != "nonce-1" || q.Get("redirect_uri") != "https://id.example.com/login/oidc/microsoft/callback" ||
		q.Get("client_id") != oidcprovider.MSClientID {
		t.Fatalf("query = %v", q)
	}
}

// U22: the authorization URL with and without a fresh login.
func TestIssue16_U22_AuthURLFresh(t *testing.T) {
	p := oidcprovider.Start(t)
	c := newClient(t, p, "organizations")
	for _, c2 := range []struct {
		provider string
		fresh    bool
		prompt   string
	}{{"microsoft", true, "login"}, {"google", true, "select_account"}, {"microsoft", false, ""}, {"google", false, ""}} {
		ap := params()
		ap.Fresh = c2.fresh
		loc, err := c.AuthCodeURL(bg, c2.provider, ap)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(loc)
		q := u.Query()
		if q.Get("prompt") != c2.prompt || q.Get("scope") != "openid email profile" {
			t.Errorf("%s fresh %v: query = %v", c2.provider, c2.fresh, q)
		}
		for _, bad := range []string{"access_type", "max_age", "login_hint", "hd"} {
			if q.Has(bad) {
				t.Errorf("%s: the URL has %s", c2.provider, bad)
			}
		}
		if strings.Contains(q.Get("scope"), "offline_access") {
			t.Error("offline_access in the scope")
		}
	}
}

func TestIssue16_GoogleExchange(t *testing.T) {
	p := oidcprovider.Start(t)
	c := newClient(t, p, "organizations")
	id, err := exchange(t, c, p, googleLogin(nil))
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "g-sub-1" || id.Email != "user@example.com" || !id.EmailVerified || id.Provider != "google" {
		t.Fatalf("identity = %+v", id)
	}
	// U11 at the adapter: the values of email_verified.
	for _, v := range []struct {
		val  any
		omit bool
		want bool
	}{{true, false, true}, {"true", false, true}, {false, false, false}, {"false", false, false}, {nil, true, false}} {
		id, err := exchange(t, c, p, googleLogin(func(l *oidcprovider.Login) { l.EmailVerified, l.OmitEmailVerified = v.val, v.omit }))
		if err != nil || id.EmailVerified != v.want {
			t.Errorf("email_verified %#v: verified %v, err %v", v.val, id.EmailVerified, err)
		}
	}
	// auth_time is read.
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	id, err = exchange(t, c, p, googleLogin(func(l *oidcprovider.Login) { l.AuthTime = at }))
	if err != nil || !id.AuthTime.Equal(at) {
		t.Fatalf("auth time %v, err %v", id.AuthTime, err)
	}
}

func TestIssue16_GoogleRefusals(t *testing.T) {
	p := oidcprovider.Start(t)
	c := newClient(t, p, "organizations", "example.com")
	other := "other-client"
	for name, mod := range map[string]func(*oidcprovider.Login){
		"no hd":          func(l *oidcprovider.Login) {},
		"hd of another":  func(l *oidcprovider.Login) { l.HD = "evil.com" },
		"two audiences":  func(l *oidcprovider.Login) { l.HD = "example.com"; l.Aud = []string{oidcprovider.GoogleClientID, "x"} },
		"azp of another": func(l *oidcprovider.Login) { l.HD = "example.com"; l.Azp = &other },
		"wrong nonce":    func(l *oidcprovider.Login) { l.HD = "example.com"; n := "other"; l.Nonce = &n },
		"expired":        func(l *oidcprovider.Login) { l.HD = "example.com"; l.Expired = true },
		"wrong issuer":   func(l *oidcprovider.Login) { l.HD = "example.com"; l.Iss = "https://evil.example.com" },
		"wrong audience": func(l *oidcprovider.Login) { l.HD = "example.com"; l.Aud = []string{"x"} },
	} {
		_, err := exchange(t, c, p, googleLogin(mod))
		if !errors.Is(err, upstreamidp.ErrToken) {
			t.Errorf("%s: err = %v, want ErrToken", name, err)
		}
	}
	if _, err := exchange(t, c, p, googleLogin(func(l *oidcprovider.Login) { l.HD = "example.com" })); err != nil {
		t.Errorf("good hd: %v", err)
	}
}

// I37 at the adapter: the iss parameter of Google. I23: a wrong client secret
// and a refusal of the token endpoint are provider errors.
func TestIssue16_GoogleIssParamAndTokenErrors(t *testing.T) {
	p := oidcprovider.Start(t)
	c := newClient(t, p, "organizations")
	for name, mod := range map[string]func(*oidcprovider.Login){
		"missing iss": func(l *oidcprovider.Login) { l.OmitIss = true },
		"wrong iss":   func(l *oidcprovider.Login) { l.IssParam = "https://evil.example.com" },
	} {
		if _, err := exchange(t, c, p, googleLogin(mod)); !errors.Is(err, upstreamidp.ErrProvider) {
			t.Errorf("%s: err = %v, want ErrProvider", name, err)
		}
	}
	if _, err := exchange(t, c, p, googleLogin(func(l *oidcprovider.Login) { l.TokenError = "invalid_grant" })); !errors.Is(err, upstreamidp.ErrProvider) {
		t.Errorf("token error: %v", err)
	}
	p.SetSecret("google", "another")
	if _, err := exchange(t, c, p, googleLogin(nil)); !errors.Is(err, upstreamidp.ErrProvider) {
		t.Errorf("wrong secret: %v", err)
	}
	// A used code does not work again.
	p.SetSecret("google", oidcprovider.GoogleSecret)
	p.Expect(googleLogin(nil))
	ap := params()
	code, iss, _ := authorize(t, c, p, "google", ap)
	ep := upstreamidp.ExchangeParams{Code: code, Verifier: ap.Verifier, Nonce: ap.Nonce, Iss: iss}
	if _, err := c.Exchange(bg, "google", ep); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exchange(bg, "google", ep); !errors.Is(err, upstreamidp.ErrProvider) {
		t.Errorf("second use of the code: %v", err)
	}
	// A wrong PKCE verifier.
	p.Expect(googleLogin(nil))
	code, iss, _ = authorize(t, c, p, "google", ap)
	if _, err := c.Exchange(bg, "google", upstreamidp.ExchangeParams{Code: code, Verifier: strings.Repeat("w", 43), Nonce: ap.Nonce, Iss: iss}); !errors.Is(err, upstreamidp.ErrProvider) {
		t.Errorf("wrong verifier: %v", err)
	}
}

// I13: Microsoft with organizations. A token of tenant A with the issuer of
// tenant A is good. A token with the issuer of tenant B and the tid of tenant A
// is refused. U2: the subject key.
func TestIssue16_MicrosoftOrganizations(t *testing.T) {
	p := oidcprovider.Start(t)
	c := newClient(t, p, "organizations")
	id, err := exchange(t, c, p, msLogin(nil))
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != oidcprovider.TenantA+":oid-1" || !id.EmailVerified || id.Email != "user@example.com" {
		t.Fatalf("identity = %+v", id)
	}
	issB := p.MicrosoftBase() + "/" + oidcprovider.TenantB + "/v2.0"
	if _, err := exchange(t, c, p, msLogin(func(l *oidcprovider.Login) { l.Iss = issB })); !errors.Is(err, upstreamidp.ErrToken) {
		t.Errorf("issuer of tenant B: %v", err)
	}
	// A tenant B token is good with its own tid.
	id, err = exchange(t, c, p, msLogin(func(l *oidcprovider.Login) { l.Tid = oidcprovider.TenantB }))
	if err != nil || id.Subject != oidcprovider.TenantB+":oid-1" {
		t.Errorf("tenant B: %+v %v", id, err)
	}
	// U12: xms_edov.
	for _, c2 := range []struct {
		edov any
		want bool
	}{{true, true}, {false, false}, {nil, false}} {
		id, err := exchange(t, c, p, msLogin(func(l *oidcprovider.Login) { l.XmsEdov = c2.edov }))
		if err != nil || id.EmailVerified != c2.want {
			t.Errorf("xms_edov %v: verified %v, err %v", c2.edov, id.EmailVerified, err)
		}
	}
	// A token with no email claim is not verified.
	id, err = exchange(t, c, p, msLogin(func(l *oidcprovider.Login) { l.Email = "" }))
	if err != nil || id.EmailVerified {
		t.Errorf("no email: %+v %v", id, err)
	}
}

// I33: the signing key rules. A token of tenant A, signed with a key whose
// issuer is of tenant B, is refused. A template key and a key with no issuer
// property are good.
func TestIssue16_MicrosoftSigningKeys(t *testing.T) {
	p := oidcprovider.Start(t)
	c := newClient(t, p, "organizations")
	for kind, ok := range map[string]bool{
		oidcprovider.KeyTemplate: true, oidcprovider.KeyNone: true, oidcprovider.KeyTenantA: true, oidcprovider.KeyTenantB: false,
	} {
		_, err := exchange(t, c, p, msLogin(func(l *oidcprovider.Login) { l.KeyKind = kind }))
		if (err == nil) != ok {
			t.Errorf("key %s: err = %v, want ok %v", kind, err, ok)
		}
		if err != nil && !errors.Is(err, upstreamidp.ErrToken) {
			t.Errorf("key %s: err = %v, want ErrToken", kind, err)
		}
	}
}

// With a tenant GUID, the normal check does the issuer, and the adapter checks
// the tid.
func TestIssue16_MicrosoftTenantGUID(t *testing.T) {
	p := oidcprovider.Start(t)
	c := newClient(t, p, oidcprovider.TenantA)
	if _, err := exchange(t, c, p, msLogin(nil)); err != nil {
		t.Fatalf("tenant A: %v", err)
	}
	if _, err := exchange(t, c, p, msLogin(func(l *oidcprovider.Login) { l.Tid = oidcprovider.TenantB })); !errors.Is(err, upstreamidp.ErrToken) {
		t.Errorf("tenant B token: %v", err)
	}
}

// I19, I24: the deadline. A slow discovery document and a slow token endpoint
// give a provider error in less than the timeout plus a margin.
func TestIssue16_Timeouts(t *testing.T) {
	p := oidcprovider.Start(t)
	c := adapter.New(adapter.Config{
		Issuer: "https://id.example.com", HTTPTimeout: time.Second, Transport: p.Transport(),
		Google: adapter.ProviderConfig{ClientID: oidcprovider.GoogleClientID, ClientSecret: oidcprovider.GoogleSecret},
	})
	p.SetDelay("discovery", 5*time.Second)
	start := time.Now()
	ctx, cancel := context.WithTimeout(bg, time.Second)
	defer cancel()
	_, err := c.AuthCodeURL(ctx, "google", params())
	if !errors.Is(err, upstreamidp.ErrProvider) || time.Since(start) > 3*time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
	// The provider is off: no call.
	if _, err := c.AuthCodeURL(bg, "microsoft", params()); !errors.Is(err, upstreamidp.ErrProvider) {
		t.Fatalf("provider off: %v", err)
	}
	if c.Enabled("microsoft") || !c.Enabled("google") || c.Enabled("okta") {
		t.Fatal("Enabled is wrong")
	}
}

// The adapter calls the test provider only. The access token and the refresh
// token of the provider have no use: the result has none of them.
func TestIssue16_OnlyTheProviderHost(t *testing.T) {
	p := oidcprovider.Start(t)
	c := newClient(t, p, "organizations")
	if _, err := exchange(t, c, p, googleLogin(nil)); err != nil {
		t.Fatal(err)
	}
	for _, h := range p.Hosts() {
		if !slices.Contains(oidcprovider.ProviderHosts(), h) {
			t.Errorf("a call to the host %q", h)
		}
	}
	if len(p.Hosts()) == 0 {
		t.Fatal("no call")
	}
}
