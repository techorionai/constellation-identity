package testserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/techorionai/constellation-platform-go/auth/clientcred"
	platformconfig "github.com/techorionai/constellation-platform-go/config"
	"gopkg.in/yaml.v3"
)

// ServiceClient is a service client with a key pair. The private key never
// leaves the test process.
type ServiceClient struct {
	ID    string
	App   string
	KID   string
	Key   *ecdsa.PrivateKey
	Roles []string
}

// NewServiceClient makes a service client with a new P-256 key pair. roles are
// role references of the clients file, for example demo:agent.
func NewServiceClient(t testing.TB, id, app string, roles ...string) ServiceClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testserver: make key: %v", err)
	}
	return ServiceClient{ID: id, App: app, KID: id + "-key-1", Key: key, Roles: roles}
}

// PEM returns the private key as PKCS #8 PEM text.
func (c ServiceClient) PEM(t testing.TB) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		t.Fatalf("testserver: encode key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// JWK returns the public key as a JWK for the clients file.
func (c ServiceClient) JWK(t testing.TB) map[string]string {
	t.Helper()
	b, err := c.Key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("testserver: encode public key: %v", err)
	}
	return map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(b[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(b[33:65]),
	}
}

type clientsFile struct {
	Clients []clientEntry `yaml:"clients"`
}

type clientEntry struct {
	ID    string     `yaml:"id"`
	App   string     `yaml:"app"`
	Keys  []keyEntry `yaml:"keys"`
	Roles []string   `yaml:"roles,omitempty"`
}

type keyEntry struct {
	KID string            `yaml:"kid"`
	JWK map[string]string `yaml:"jwk"`
}

// WriteClientsFile writes a clients file in a temporary folder and returns its
// path.
func WriteClientsFile(t testing.TB, clients ...ServiceClient) string {
	t.Helper()
	var f clientsFile
	for _, c := range clients {
		f.Clients = append(f.Clients, clientEntry{
			ID: c.ID, App: c.App, Roles: c.Roles,
			Keys: []keyEntry{{KID: c.KID, JWK: c.JWK(t)}},
		})
	}
	data, err := yaml.Marshal(f)
	if err != nil {
		t.Fatalf("testserver: encode clients file: %v", err)
	}
	path := filepath.Join(t.TempDir(), "clients.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("testserver: write clients file: %v", err)
	}
	return path
}

// WithClients writes a clients file for the clients and uses it.
func WithClients(t testing.TB, clients ...ServiceClient) Option {
	t.Helper()
	return WithClientsFile(WriteClientsFile(t, clients...))
}

// TokenSource returns an auth/clientcred token source for the client. The
// issuer is the issuer of the server. The token URL is the public URL. Both use
// http, so the config sets AllowInsecureHTTP.
func (s *Server) TokenSource(t testing.TB, c ServiceClient) *clientcred.Source {
	t.Helper()
	src, err := clientcred.New(clientcred.Config{
		ID:                c.ID,
		KeyID:             c.KID,
		PrivateKey:        platformconfig.Secret(c.PEM(t)),
		Issuer:            s.Config.Issuer,
		TokenURL:          s.PublicURL + "/oauth/token",
		HTTPTimeout:       10 * time.Second,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("testserver: token source: %v", err)
	}
	return src
}

// Assertion signs a client assertion with the key of the client. The default
// claims are the claims that auth/clientcred sends. change can set, replace, or
// delete (with a nil value) a claim, and set a header member.
func (s *Server) Assertion(t testing.TB, c ServiceClient, change func(claims, header map[string]any)) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": c.ID, "sub": c.ID, "aud": s.Config.Issuer,
		"jti": randomID(t), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}
	header := map[string]any{}
	if change != nil {
		change(claims, header)
	}
	for k, v := range claims {
		if v == nil {
			delete(claims, k)
		}
	}
	return SignAssertion(t, c.Key, c.KID, claims, header)
}

// SignAssertion signs claims with ES256. header gives extra members.
func SignAssertion(t testing.TB, key *ecdsa.PrivateKey, kid string, claims, header map[string]any) string {
	t.Helper()
	opts := (&gojose.SignerOptions{}).WithType("JWT")
	for k, v := range header {
		opts = opts.WithHeader(gojose.HeaderKey(k), v)
	}
	jwk := gojose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(gojose.ES256)}
	if kid == "" {
		jwk.KeyID = ""
	}
	sig, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.ES256, Key: jwk}, opts)
	if err != nil {
		t.Fatalf("testserver: make signer: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("testserver: encode claims: %v", err)
	}
	obj, err := sig.Sign(payload)
	if err != nil {
		t.Fatalf("testserver: sign: %v", err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("testserver: serialize: %v", err)
	}
	return out
}

func randomID(t testing.TB) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("testserver: random id: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// TokenForm returns the form of a client credentials request.
func TokenForm(assertion, audience, scope string) url.Values {
	v := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	if audience != "" {
		v.Set("audience", audience)
	}
	if scope != "" {
		v.Set("scope", scope)
	}
	return v
}

// PostToken sends a token request with a form.
func (s *Server) PostToken(t testing.TB, form url.Values) (Response, []byte) {
	t.Helper()
	return s.Post(t, "/oauth/token", form.Encode())
}

// Do sends a request with a bearer token and a JSON body to the public URL.
// An empty token sends no Authorization header. An empty body sends no body.
func (s *Server) Do(t testing.TB, method, path, token, body string) (Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, s.PublicURL+path, r)
	if err != nil {
		t.Fatalf("testserver: request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("testserver: %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testserver: read body: %v", err)
	}
	return Response{StatusCode: resp.StatusCode, Header: resp.Header}, b
}
