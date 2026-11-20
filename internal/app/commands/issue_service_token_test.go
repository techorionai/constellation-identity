package commands_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	gojose "github.com/go-jose/go-jose/v4"

	"github.com/techorionai/constellation-identity/internal/adapters/jose"
	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
	"github.com/techorionai/constellation-identity/internal/ports/tokensigner"
)

const issuer = "https://id.example.com"

var now = time.Unix(1_800_000_000, 0)

// fakeClients is an in-memory client repository.
type fakeClients struct {
	clients map[string]domain.Client
	keys    map[string][]domain.ClientKey
}

func (f *fakeClients) UpsertConfig(context.Context, domain.ClientConfig) (bool, error) {
	return true, nil
}
func (f *fakeClients) DisableConfigNotIn(context.Context, []string) ([]string, error) {
	return nil, nil
}
func (f *fakeClients) Get(_ context.Context, id string) (domain.Client, error) {
	c, ok := f.clients[id]
	if !ok {
		return domain.Client{}, clients.ErrNotFound
	}
	return c, nil
}
func (f *fakeClients) Keys(_ context.Context, id string) ([]domain.ClientKey, error) {
	return f.keys[id], nil
}
func (f *fakeClients) WithLock(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

// fakeRoles returns the permissions of the roles that the test sets.
type fakeRoles struct {
	assigned []string
	implicit map[domain.RoleRef][]string
}

func (f *fakeRoles) Assignments(context.Context, string) ([]domain.RoleAssignment, error) {
	return nil, nil
}
func (f *fakeRoles) GrantedPermissions(_ context.Context, _ string, implicit ...domain.RoleRef) ([]string, error) {
	out := append([]string(nil), f.assigned...)
	for _, ref := range implicit {
		out = append(out, f.implicit[ref]...)
	}
	return out, nil
}

type fakeManifests struct{ apps map[string]bool }

func (f *fakeManifests) HasManifest(_ context.Context, app string) (bool, error) {
	return f.apps[app], nil
}
func (f *fakeManifests) Publish(context.Context, domain.Manifest, string) (domain.PublishedManifest, error) {
	return domain.PublishedManifest{}, errors.New("not used")
}
func (f *fakeManifests) Get(context.Context, string) (domain.PublishedManifest, error) {
	return domain.PublishedManifest{}, errors.New("not used")
}
func (f *fakeManifests) List(context.Context, string, int) ([]domain.PublishedManifest, error) {
	return nil, errors.New("not used")
}
func (f *fakeManifests) Role(context.Context, domain.RoleRef) (domain.Role, error) {
	return domain.Role{}, errors.New("not used")
}
func (f *fakeManifests) Roles(context.Context, string, domain.RoleRef, int) ([]domain.Role, error) {
	return nil, errors.New("not used")
}

type fakeJTI struct {
	used  map[string]bool
	err   error
	calls int
	ttl   time.Duration
}

func (f *fakeJTI) Claim(_ context.Context, clientID, jti string, ttl time.Duration) (bool, error) {
	f.calls++
	f.ttl = ttl
	if f.err != nil {
		return false, f.err
	}
	k := clientID + "/" + jti
	if f.used[k] {
		return false, nil
	}
	f.used[k] = true
	return true, nil
}

type fakeKeySource struct{ key tokensigner.Key }

func (f fakeKeySource) ActiveKey() (tokensigner.Key, error) { return f.key, nil }

// fixture holds a command and the key pair of the client "helpdesk".
type fixture struct {
	cmd     *commands.IssueServiceTokenCommand
	jti     *fakeJTI
	roles   *fakeRoles
	clients *fakeClients
	key     *ecdsa.PrivateKey
	sign    *ecdsa.PrivateKey
	log     *bytes.Buffer
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwkOf(t *testing.T, k *ecdsa.PrivateKey, kid string) domain.PublicJWK {
	t.Helper()
	b, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return domain.PublicJWK{
		Kty: "EC", Crv: "P-256", Kid: kid,
		X: base64.RawURLEncoding.EncodeToString(b[1:33]),
		Y: base64.RawURLEncoding.EncodeToString(b[33:65]),
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{key: newKey(t), sign: newKey(t), log: &bytes.Buffer{}}
	f.clients = &fakeClients{
		clients: map[string]domain.Client{
			"helpdesk": {ID: "helpdesk", Type: domain.ClientTypeService, App: "helpdesk"},
			"other":    {ID: "other", Type: domain.ClientTypeService, App: "other"},
			"off":      {ID: "off", Type: domain.ClientTypeService, App: "off", Disabled: true},
			"web":      {ID: "web", Type: "public", App: "web"},
		},
		keys: map[string][]domain.ClientKey{
			"helpdesk": {{ClientID: "helpdesk", KID: "k1", PublicJWK: jwkOf(t, f.key, "k1")}},
			"other":    {{ClientID: "other", KID: "ok", PublicJWK: jwkOf(t, newKey(t), "ok")}},
			"off":      {{ClientID: "off", KID: "k1", PublicJWK: jwkOf(t, f.key, "k1")}},
			"web":      {{ClientID: "web", KID: "k1", PublicJWK: jwkOf(t, f.key, "k1")}},
		},
	}
	f.jti = &fakeJTI{used: map[string]bool{}}
	f.roles = &fakeRoles{
		assigned: []string{"demo:ticket:read"},
		implicit: map[domain.RoleRef][]string{domain.ServiceRole: {"identity:manifest:publish"}},
	}
	counter := 0
	cmd, err := commands.NewIssueServiceToken(commands.IssueServiceTokenDeps{
		Issuer:      issuer,
		Clients:     f.clients,
		ClientRoles: f.roles,
		Manifests:   &fakeManifests{apps: map[string]bool{"demo": true, "identity": true}},
		JTI:         f.jti,
		Keys:        fakeKeySource{key: tokensigner.Key{KID: "sig-1", Private: f.sign}},
		Signer:      jose.Signer{},
		Parser:      jose.AssertionParser{},
		Log:         slog.New(slog.NewTextHandler(f.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:         func() time.Time { return now },
		NewID:       func() string { counter++; return fmt.Sprintf("token-%d", counter) },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.cmd = cmd
	return f
}

// assertion signs the claims with ES256. change edits the default claims. A
// nil value deletes a claim.
func (f *fixture) assertion(t *testing.T, change func(claims map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss": "helpdesk", "sub": "helpdesk", "aud": issuer, "jti": "jti-" + randString(t),
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}
	if change != nil {
		change(claims)
	}
	for k, v := range claims {
		if v == nil {
			delete(claims, k)
		}
	}
	return signES256(t, f.key, "k1", claims)
}

func randString(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	jwk := gojose.JSONWebKey{Key: key, KeyID: kid}
	sig, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.ES256, Key: jwk}, (&gojose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := sig.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := obj.CompactSerialize()
	return s
}

func request(assertion string) commands.IssueServiceToken {
	return commands.IssueServiceToken{
		GrantType:     "client_credentials",
		AssertionType: domain.AssertionType,
		Assertion:     assertion,
		Audience:      "demo",
		Scope:         "demo:ticket:read",
	}
}

func oauthCode(t *testing.T, err error) string {
	t.Helper()
	oe, ok := apperrors.AsOAuthError(err)
	if !ok {
		t.Fatalf("error = %v, want an OAuthError", err)
	}
	return oe.Code
}

// Issue2_U7b: the scope identity:manifest:publish is granted through the
// implicit role identity:service, with no assignment.
func TestIssue2_U7b_ImplicitServiceRole(t *testing.T) {
	f := newFixture(t)
	f.roles.assigned = nil
	in := request(f.assertion(t, nil))
	in.Audience, in.Scope = "identity", "identity:manifest:publish"
	res, err := f.cmd.Execute(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Scope != "identity:manifest:publish" || res.ExpiresIn != 300 {
		t.Fatalf("result = %+v", res)
	}
}

// Issue2_U9: the token matches AccessTokenClaims.
func TestIssue2_U9_IssuedToken(t *testing.T) {
	f := newFixture(t)
	res, err := f.cmd.Execute(context.Background(), request(f.assertion(t, nil)))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := gojose.ParseSignedCompact(res.AccessToken, []gojose.SignatureAlgorithm{gojose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	h := obj.Signatures[0].Header
	if h.KeyID != "sig-1" || h.Algorithm != "ES256" || h.ExtraHeaders[gojose.HeaderType] != "at+jwt" {
		t.Fatalf("header = %+v", h)
	}
	payload, err := obj.Verify(&f.sign.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	if c["iss"] != issuer || c["aud"] != "demo" || c["sub"] != "helpdesk" || c["client_id"] != "helpdesk" ||
		c["principal_type"] != "service" || c["scope"] != "demo:ticket:read" || c["jti"] == "" {
		t.Fatalf("claims = %v", c)
	}
	if c["iat"] != float64(now.Unix()) || c["nbf"] != float64(now.Unix()) || c["exp"] != float64(now.Add(5*time.Minute).Unix()) {
		t.Fatalf("times = %v %v %v", c["iat"], c["nbf"], c["exp"])
	}
	if _, ok := c["act"]; ok {
		t.Fatal("the token has an act claim")
	}
}

// Issue2_U6 and U7: scope errors through the command.
func TestIssue2_ScopeErrors(t *testing.T) {
	f := newFixture(t)
	for name, scope := range map[string]string{
		"scope of another app":    "demo:ticket:read helpdesk:ticket:read",
		"scope not granted":       "demo:ticket:write",
		"no scope":                "",
		"scope of a pending role": "demo:agent:pending",
	} {
		in := request(f.assertion(t, nil))
		in.Scope = scope
		_, err := f.cmd.Execute(context.Background(), in)
		if got := oauthCode(t, err); got != "invalid_scope" {
			t.Errorf("%s: code = %s", name, got)
		}
	}
}

// Issue2_U10 and U10a to U10i: assertion errors give invalid_client.
func TestIssue2_AssertionErrors(t *testing.T) {
	cases := map[string]func(c map[string]any){
		"U10 lifetime of 10 minutes":  func(c map[string]any) { c["exp"] = now.Add(10 * time.Minute).Unix() },
		"U10a exp in the past":        func(c map[string]any) { c["exp"] = now.Add(-60 * time.Second).Unix() },
		"U10b iat in the future":      func(c map[string]any) { c["iat"] = now.Add(2 * time.Minute).Unix() },
		"U10c nbf in the future":      func(c map[string]any) { c["nbf"] = now.Add(2 * time.Minute).Unix() },
		"U10f iss is not sub":         func(c map[string]any) { c["iss"] = "other" },
		"U10h jti of 257 characters":  func(c map[string]any) { c["jti"] = strings.Repeat("j", 257) },
		"U10i aud is the token URL":   func(c map[string]any) { c["aud"] = issuer + "/oauth/token" },
		"U10i aud is another URL":     func(c map[string]any) { c["aud"] = "https://other.example.com" },
		"jti missing":                 func(c map[string]any) { c["jti"] = nil },
		"exp missing":                 func(c map[string]any) { c["exp"] = nil },
		"exp is a string":             func(c map[string]any) { c["exp"] = "soon" },
		"sub of an unknown client":    func(c map[string]any) { c["sub"], c["iss"] = "nobody", "nobody" },
		"sub of a disabled client":    func(c map[string]any) { c["sub"], c["iss"] = "off", "off" },
		"aud is an array without iss": func(c map[string]any) { c["aud"] = []string{"a", "b"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			_, err := f.cmd.Execute(context.Background(), request(f.assertion(t, change)))
			if got := oauthCode(t, err); got != "invalid_client" {
				t.Fatalf("code = %s, error = %v", got, err)
			}
		})
	}

	t.Run("U10a makes no jti store call", func(t *testing.T) {
		f := newFixture(t)
		_, err := f.cmd.Execute(context.Background(), request(f.assertion(t, cases["U10a exp in the past"])))
		if oauthCode(t, err) != "invalid_client" || f.jti.calls != 0 {
			t.Fatalf("error = %v, calls = %d", err, f.jti.calls)
		}
	})

	t.Run("U10i aud array with the issuer passes", func(t *testing.T) {
		f := newFixture(t)
		_, err := f.cmd.Execute(context.Background(), request(f.assertion(t, func(c map[string]any) {
			c["aud"] = []string{"https://other.example.com", issuer}
		})))
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("U10g form client_id is not sub", func(t *testing.T) {
		f := newFixture(t)
		in := request(f.assertion(t, nil))
		in.ClientID = "other"
		_, err := f.cmd.Execute(context.Background(), in)
		if oauthCode(t, err) != "invalid_client" {
			t.Fatalf("error = %v", err)
		}
		in = request(f.assertion(t, nil))
		in.ClientID = "helpdesk"
		if _, err := f.cmd.Execute(context.Background(), in); err != nil {
			t.Fatalf("matching client_id: %v", err)
		}
	})

	t.Run("U10j the jti is kept for the replay TTL", func(t *testing.T) {
		f := newFixture(t)
		_, err := f.cmd.Execute(context.Background(), request(f.assertion(t, func(c map[string]any) {
			c["exp"] = now.Add(5 * time.Second).Unix()
		})))
		if err != nil || f.jti.ttl != 35*time.Second {
			t.Fatalf("error = %v, ttl = %s", err, f.jti.ttl)
		}
	})
}

// Issue2_U10d: an assertion with another alg gives invalid_client.
func TestIssue2_U10d_Algorithms(t *testing.T) {
	f := newFixture(t)
	claims := map[string]any{"iss": "helpdesk", "sub": "helpdesk", "aud": issuer, "jti": "x", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	payload, _ := json.Marshal(claims)

	hs, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, &gojose.SignerOptions{ExtraHeaders: map[gojose.HeaderKey]any{"kid": "k1"}})
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.RS256, Key: rk}, &gojose.SignerOptions{ExtraHeaders: map[gojose.HeaderKey]any{"kid": "k1"}})
	if err != nil {
		t.Fatal(err)
	}
	var assertions []string
	for _, s := range []gojose.Signer{hs, rs} {
		obj, err := s.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := obj.CompactSerialize()
		assertions = append(assertions, c)
	}
	enc := base64.RawURLEncoding
	assertions = append(assertions, enc.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`))+"."+enc.EncodeToString(payload)+".")
	for i, a := range assertions {
		_, err := f.cmd.Execute(context.Background(), request(a))
		if got := oauthCode(t, err); got != "invalid_client" {
			t.Errorf("assertion %d: code = %s", i, got)
		}
	}
}

// Issue2_U10e: no kid, or the kid of another client.
func TestIssue2_U10e_KeyID(t *testing.T) {
	f := newFixture(t)
	claims := map[string]any{"iss": "helpdesk", "sub": "helpdesk", "aud": issuer, "jti": "x", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	for name, kid := range map[string]string{"no kid": "", "kid of another client": "ok", "unknown kid": "zz"} {
		_, err := f.cmd.Execute(context.Background(), request(signES256(t, f.key, kid, claims)))
		if got := oauthCode(t, err); got != "invalid_client" {
			t.Errorf("%s: code = %s", name, got)
		}
	}
	// A valid kid with a signature of another key.
	_, err := f.cmd.Execute(context.Background(), request(signES256(t, newKey(t), "k1", claims)))
	if oauthCode(t, err) != "invalid_client" {
		t.Fatalf("error = %v", err)
	}
}

// Issue2_U10k: a public client gets unauthorized_client.
func TestIssue2_U10k_PublicClient(t *testing.T) {
	f := newFixture(t)
	_, err := f.cmd.Execute(context.Background(), request(f.assertion(t, func(c map[string]any) {
		c["sub"], c["iss"] = "web", "web"
	})))
	if got := oauthCode(t, err); got != "unauthorized_client" {
		t.Fatalf("code = %s", got)
	}
}

// The request checks: grant, assertion type, second authentication.
func TestIssue2_RequestErrors(t *testing.T) {
	f := newFixture(t)
	a := f.assertion(t, nil)
	cases := map[string]struct {
		change func(*commands.IssueServiceToken)
		code   string
	}{
		"no grant_type":         {func(in *commands.IssueServiceToken) { in.GrantType = "" }, "invalid_request"},
		"another grant":         {func(in *commands.IssueServiceToken) { in.GrantType = "password" }, "unsupported_grant_type"},
		"no assertion":          {func(in *commands.IssueServiceToken) { in.Assertion = "" }, "invalid_request"},
		"another type":          {func(in *commands.IssueServiceToken) { in.AssertionType = "x" }, "invalid_request"},
		"client secret":         {func(in *commands.IssueServiceToken) { in.SecondAuthentication = true }, "invalid_request"},
		"repeated parameter":    {func(in *commands.IssueServiceToken) { in.RepeatedParameter = true }, "invalid_request"},
		"not a JWT":             {func(in *commands.IssueServiceToken) { in.Assertion = "abc" }, "invalid_client"},
		"audience missing":      {func(in *commands.IssueServiceToken) { in.Audience = "" }, "invalid_target"},
		"audience unknown":      {func(in *commands.IssueServiceToken) { in.Audience = "nope" }, "invalid_target"},
		"audience is not a key": {func(in *commands.IssueServiceToken) { in.Audience = "No:pe" }, "invalid_target"},
	}
	for name, c := range cases {
		in := request(a)
		c.change(&in)
		// Each case uses its own assertion, because a jti works one time.
		if in.Assertion == a {
			in.Assertion = f.assertion(t, nil)
		}
		_, err := f.cmd.Execute(context.Background(), in)
		if got := oauthCode(t, err); got != c.code {
			t.Errorf("%s: code = %s, want %s", name, got, c.code)
		}
	}
}

// A store error gives temporarily_unavailable and no token. A used jti gives
// invalid_client.
func TestIssue2_ReplayStore(t *testing.T) {
	f := newFixture(t)
	a := f.assertion(t, nil)
	if _, err := f.cmd.Execute(context.Background(), request(a)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.cmd.Execute(context.Background(), request(a)); oauthCode(t, err) != "invalid_client" {
		t.Fatalf("second use: %v", err)
	}
	f.jti.err = errors.New("valkey is down")
	res, err := f.cmd.Execute(context.Background(), request(f.assertion(t, nil)))
	if oauthCode(t, err) != "temporarily_unavailable" || res.AccessToken != "" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// Issue2_U13: a failed request writes one warn record with the code. No record
// has the assertion or the form.
func TestIssue2_U13_FailureLog(t *testing.T) {
	f := newFixture(t)
	good := f.assertion(t, nil)
	// Change the last characters of the signature.
	bad := good[:len(good)-6] + "AAAAAA"
	in := request(bad)
	in.Scope = "demo:marker:read"
	_, err := f.cmd.Execute(context.Background(), in)
	if oauthCode(t, err) != "invalid_client" {
		t.Fatalf("error = %v", err)
	}
	logText := f.log.String()
	warns := 0
	for _, line := range strings.Split(strings.TrimSpace(logText), "\n") {
		if strings.Contains(line, "level=WARN") {
			warns++
			if !strings.Contains(line, "error_code=invalid_client") {
				t.Fatalf("warn record = %s", line)
			}
		}
	}
	if warns != 1 {
		t.Fatalf("warn records = %d, log:\n%s", warns, logText)
	}
	for _, secret := range []string{bad, good, bad[:40], "demo:marker", "client_assertion"} {
		if strings.Contains(logText, secret) {
			t.Fatalf("the log has %q", secret)
		}
	}
	if !strings.Contains(logText, "client.id_unverified=helpdesk") {
		t.Fatalf("the log has no unverified client ID:\n%s", logText)
	}
}

// Issue2_U10m: the log field of an unverified client ID is cut at a character
// boundary. The value is valid UTF-8.
func TestIssue2_U10m_LogTruncatesAtCharacter(t *testing.T) {
	f := newFixture(t)
	// 63 ASCII bytes, then a 3-byte character, so byte 64 is inside it.
	sub := strings.Repeat("a", 63) + "\u20ac"
	in := request(f.assertion(t, func(c map[string]any) { c["sub"] = sub }))
	if _, err := f.cmd.Execute(context.Background(), in); oauthCode(t, err) != "invalid_client" {
		t.Fatalf("error = %v", err)
	}
	logText := f.log.String()
	if !utf8.ValidString(logText) {
		t.Fatalf("the log has invalid UTF-8: %q", logText)
	}
	want := "client.id_unverified=" + strings.Repeat("a", 63)
	if !strings.Contains(logText, want+"\n") && !strings.Contains(logText, want+" ") {
		t.Fatalf("the log field is not cut at the character:\n%s", logText)
	}
}
