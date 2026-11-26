// Package oidc is the adapter of the port upstreamidp. It is an OIDC client for
// Google and Microsoft work accounts. It uses github.com/coreos/go-oidc/v3 and
// golang.org/x/oauth2. The service is not an OIDC provider library: it uses
// these libraries only as a client of the upstream providers.
package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/upstreamidp"
)

// scopes are the only scopes that the service asks for. The service asks for no
// offline access, so no provider gives a refresh token.
var scopes = []string{"openid", "email", "profile"}

// discoveryTTL is the time that the service keeps a discovery document.
const discoveryTTL = time.Hour

// maxIDTokenBytes is the largest ID token that the service reads.
const maxIDTokenBytes = 16 << 10

// ProviderConfig is the setting of one provider. A provider is on when it has a
// client ID.
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	// AllowedDomains is the list of the Google hosted domains (hd). An empty list
	// allows all accounts.
	AllowedDomains []string
	// Tenant is the Microsoft tenant: a GUID or "organizations".
	Tenant string
	// BaseURL replaces the issuer of Google, or the Microsoft login base. A test
	// uses it to point the adapter at a test provider. Production code leaves it
	// empty.
	BaseURL string
}

// Config is the setting of the adapter.
type Config struct {
	// Issuer is the issuer URL of this service. The redirect URI of a provider is
	// <Issuer>/login/oidc/<provider>/callback.
	Issuer    string
	Google    ProviderConfig
	Microsoft ProviderConfig
	// HTTPTimeout is the time limit of one call to a provider.
	HTTPTimeout time.Duration
	// Now is the clock. The default is time.Now.
	Now func() time.Time
}

// Client is the adapter.
type Client struct {
	cfg  Config
	http *http.Client
	now  func() time.Time

	mu    sync.Mutex
	found map[string]*discovered
}

var _ upstreamidp.Client = (*Client)(nil)

// discovered is a provider after discovery.
type discovered struct {
	at       time.Time
	oauth    oauth2.Endpoint
	verifier *gooidc.IDTokenVerifier
}

// New makes the adapter. The HTTP client has the timeout and never follows a
// redirect.
func New(cfg Config) *Client {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout:       cfg.HTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:   cfg.Now,
		found: map[string]*discovered{},
	}
}

func (c *Client) provider(provider string) (ProviderConfig, bool) {
	switch provider {
	case domain.ProviderGoogle:
		return c.cfg.Google, c.cfg.Google.ClientID != ""
	case domain.ProviderMicrosoft:
		return c.cfg.Microsoft, c.cfg.Microsoft.ClientID != ""
	}
	return ProviderConfig{}, false
}

// Enabled reports whether the provider is on.
func (c *Client) Enabled(provider string) bool {
	_, ok := c.provider(provider)
	return ok
}

// googleIssuer returns the issuer of the Google discovery document.
func (c *Client) googleIssuer() string {
	if c.cfg.Google.BaseURL != "" {
		return strings.TrimSuffix(c.cfg.Google.BaseURL, "/")
	}
	return domain.GoogleIssuer
}

// microsoftBase returns the base URL of the Microsoft login service.
func (c *Client) microsoftBase() string {
	if c.cfg.Microsoft.BaseURL != "" {
		return strings.TrimSuffix(c.cfg.Microsoft.BaseURL, "/")
	}
	return domain.MicrosoftLoginBase
}

func (c *Client) redirectURI(provider string) string {
	return c.cfg.Issuer + "/login/oidc/" + provider + "/callback"
}

// discover reads the discovery document, or uses the copy in memory.
func (c *Client) discover(ctx context.Context, provider string) (*discovered, error) {
	c.mu.Lock()
	d, ok := c.found[provider]
	c.mu.Unlock()
	if ok && c.now().Sub(d.at) < discoveryTTL {
		return d, nil
	}
	pc, on := c.provider(provider)
	if !on {
		return nil, fmt.Errorf("%w: the provider is off", upstreamidp.ErrProvider)
	}
	ctx = gooidc.ClientContext(ctx, c.http)
	var err error
	switch provider {
	case domain.ProviderGoogle:
		d, err = c.discoverGoogle(ctx, pc)
	default:
		d, err = c.discoverMicrosoft(ctx, pc)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: discovery: %w", upstreamidp.ErrProvider, err)
	}
	d.at = c.now()
	c.mu.Lock()
	c.found[provider] = d
	c.mu.Unlock()
	return d, nil
}

func (c *Client) discoverGoogle(ctx context.Context, pc ProviderConfig) (*discovered, error) {
	p, err := gooidc.NewProvider(ctx, c.googleIssuer())
	if err != nil {
		return nil, err
	}
	return &discovered{oauth: p.Endpoint(), verifier: p.VerifierContext(ctx, &gooidc.Config{ClientID: pc.ClientID, Now: c.now})}, nil
}

func (c *Client) discoverMicrosoft(ctx context.Context, pc ProviderConfig) (*discovered, error) {
	base := c.microsoftBase()
	if pc.Tenant != "" && pc.Tenant != domain.MicrosoftOrganizations {
		// A tenant GUID: the issuer is exact, and the normal check does it.
		p, err := gooidc.NewProvider(ctx, base+"/"+pc.Tenant+"/v2.0")
		if err != nil {
			return nil, err
		}
		return &discovered{oauth: p.Endpoint(), verifier: p.VerifierContext(ctx, &gooidc.Config{ClientID: pc.ClientID, Now: c.now})}, nil
	}
	// The tenant "organizations": the discovery document has the issuer with the
	// text {tenantid}. The check of the issuer and of the signing key is our own.
	template := base + "/" + domain.TenantTemplate + "/v2.0"
	p, err := gooidc.NewProvider(gooidc.InsecureIssuerURLContext(ctx, template), base+"/"+domain.MicrosoftOrganizations+"/v2.0")
	if err != nil {
		return nil, err
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := p.Claims(&doc); err != nil || doc.JWKSURI == "" {
		return nil, errors.New("the discovery document has no jwks_uri")
	}
	keys := &msKeySet{url: doc.JWKSURI, client: c.http}
	// The issuer check is off here. The method checkMicrosoft does it.
	v := gooidc.NewVerifier(template, keys, &gooidc.Config{ClientID: pc.ClientID, SkipIssuerCheck: true, Now: c.now})
	return &discovered{oauth: p.Endpoint(), verifier: v}, nil
}

func (c *Client) oauthConfig(provider string, pc ProviderConfig, d *discovered) *oauth2.Config {
	return &oauth2.Config{
		ClientID: pc.ClientID, ClientSecret: pc.ClientSecret, Endpoint: d.oauth,
		RedirectURL: c.redirectURI(provider), Scopes: scopes,
	}
}

// AuthCodeURL returns the URL of the authorization request. The request has a
// PKCE challenge (S256), the nonce, and response_mode=query. With Fresh it asks
// the provider for a new login.
func (c *Client) AuthCodeURL(ctx context.Context, provider string, p upstreamidp.AuthParams) (string, error) {
	d, err := c.discover(ctx, provider)
	if err != nil {
		return "", err
	}
	pc, _ := c.provider(provider)
	opts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(p.Verifier),
		oauth2.SetAuthURLParam("nonce", p.Nonce),
		oauth2.SetAuthURLParam("response_mode", "query"),
	}
	if p.Fresh {
		prompt := "select_account"
		if provider == domain.ProviderMicrosoft {
			prompt = "login"
		}
		opts = append(opts, oauth2.SetAuthURLParam("prompt", prompt))
	}
	return c.oauthConfig(provider, pc, d).AuthCodeURL(p.State, opts...), nil
}

// Exchange trades the code for the ID token, checks the token, and returns the
// identity. It discards the access token and the refresh token.
func (c *Client) Exchange(ctx context.Context, provider string, p upstreamidp.ExchangeParams) (domain.UpstreamIdentity, error) {
	pc, on := c.provider(provider)
	if !on {
		return domain.UpstreamIdentity{}, fmt.Errorf("%w: the provider is off", upstreamidp.ErrProvider)
	}
	if provider == domain.ProviderGoogle && !domain.IssParamOK(provider, p.Iss, c.googleIssuer()) {
		return domain.UpstreamIdentity{}, fmt.Errorf("%w: the iss parameter is not right", upstreamidp.ErrProvider)
	}
	d, err := c.discover(ctx, provider)
	if err != nil {
		return domain.UpstreamIdentity{}, err
	}
	ctx = gooidc.ClientContext(ctx, c.http)
	tok, err := c.oauthConfig(provider, pc, d).Exchange(ctx, p.Code, oauth2.VerifierOption(p.Verifier))
	if err != nil {
		return domain.UpstreamIdentity{}, fmt.Errorf("%w: token request: %w", upstreamidp.ErrProvider, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" || len(raw) > maxIDTokenBytes {
		return domain.UpstreamIdentity{}, fmt.Errorf("%w: no ID token", upstreamidp.ErrToken)
	}
	// The access token and the refresh token have no use. They stay in this
	// function only, and nothing keeps or logs them.
	idToken, err := d.verifier.Verify(ctx, raw)
	if err != nil {
		var transport interface{ Timeout() bool }
		if errors.As(err, &transport) {
			return domain.UpstreamIdentity{}, fmt.Errorf("%w: keys: %w", upstreamidp.ErrProvider, err)
		}
		return domain.UpstreamIdentity{}, fmt.Errorf("%w: %w", upstreamidp.ErrToken, err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(p.Nonce)) != 1 || p.Nonce == "" {
		return domain.UpstreamIdentity{}, fmt.Errorf("%w: nonce", upstreamidp.ErrToken)
	}
	var claims struct {
		Azp           string `json:"azp"`
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		HD            string `json:"hd"`
		XmsEdov       any    `json:"xms_edov"`
		Tid           string `json:"tid"`
		Oid           string `json:"oid"`
		AuthTime      int64  `json:"auth_time"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return domain.UpstreamIdentity{}, fmt.Errorf("%w: claims", upstreamidp.ErrToken)
	}
	if err := domain.CheckAudience(idToken.Audience, claims.Azp, pc.ClientID); err != nil {
		return domain.UpstreamIdentity{}, fmt.Errorf("%w: audience", upstreamidp.ErrToken)
	}
	id := domain.UpstreamIdentity{Provider: provider, Email: claims.Email, IssuedAt: idToken.IssuedAt}
	if claims.AuthTime > 0 {
		id.AuthTime = time.Unix(claims.AuthTime, 0).UTC()
	}
	switch provider {
	case domain.ProviderGoogle:
		if idToken.Subject == "" || !domain.GoogleHDAllowed(pc.AllowedDomains, claims.HD) {
			return domain.UpstreamIdentity{}, fmt.Errorf("%w: subject or hosted domain", upstreamidp.ErrToken)
		}
		id.Subject = idToken.Subject
		id.EmailVerified = claims.Email != "" && domain.VerifiedFlag(claims.EmailVerified)
	default:
		if err := c.checkMicrosoft(pc, idToken.Issuer, claims.Tid); err != nil {
			return domain.UpstreamIdentity{}, err
		}
		sub, err := domain.MicrosoftSubject(claims.Tid, claims.Oid)
		if err != nil {
			return domain.UpstreamIdentity{}, fmt.Errorf("%w: subject", upstreamidp.ErrToken)
		}
		id.Subject = sub
		id.EmailVerified = domain.MicrosoftEmailVerified(claims.Email, claims.XmsEdov)
	}
	return id, nil
}

// checkMicrosoft does the issuer rules of a Microsoft token. With a tenant GUID,
// the normal check did the issuer and this function checks the tid. With
// "organizations", this function does the issuer rules.
func (c *Client) checkMicrosoft(pc ProviderConfig, iss, tid string) error {
	if pc.Tenant != "" && pc.Tenant != domain.MicrosoftOrganizations {
		if !strings.EqualFold(tid, pc.Tenant) {
			return fmt.Errorf("%w: tenant", upstreamidp.ErrToken)
		}
		return nil
	}
	if err := domain.CheckMicrosoftIssuer(c.microsoftBase(), iss, tid); err != nil {
		return fmt.Errorf("%w: issuer", upstreamidp.ErrToken)
	}
	return nil
}
