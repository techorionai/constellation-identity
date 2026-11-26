package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/techorionai/constellation-platform-go/auth/jwt"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// KeySet gives the public signing keys.
type KeySet interface {
	JWKS() []domain.PublicJWK
}

// VerifierConfig returns the config of the in-process verifier of the /v1
// routes. The audience is identity. AllowInsecureHTTP is true only when the
// issuer uses http and its host is localhost, 127.0.0.1, or [::1]. This is the
// loopback rule of IDENTITY_ISSUER.
func VerifierConfig(issuer string) jwt.Config {
	return jwt.Config{
		Issuer:   issuer,
		Audience: domain.IdentityApp,
		JWKSURL:  strings.TrimRight(issuer, "/") + "/.well-known/jwks.json",
		// The key source is in this process, so a refresh is cheap.
		RefreshInterval:    time.Minute,
		MinRefetchInterval: time.Second,
		AllowInsecureHTTP:  isLoopbackHTTP(issuer),
	}
}

func isLoopbackHTTP(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// NewVerifier makes the verifier of the /v1 routes. It reads the keys from the
// key set of this process. It makes no network request. If the config is not
// valid, for example an http issuer with a host that is not a loopback host,
// the error names the issuer, and the service does not start.
func NewVerifier(issuer string, keys KeySet, opts ...jwt.Option) (*jwt.Verifier, error) {
	client := &http.Client{Transport: jwksTransport{keys: keys}}
	v, err := jwt.New(VerifierConfig(issuer), append([]jwt.Option{jwt.WithHTTPClient(client)}, opts...)...)
	if err != nil {
		return nil, fmt.Errorf("the issuer %q cannot be used to verify tokens: %w", issuer, err)
	}
	return v, nil
}

// jwksTransport answers the JWKS request of the verifier from the key set.
type jwksTransport struct{ keys KeySet }

func (t jwksTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := json.Marshal(struct {
		Keys []domain.PublicJWK `json:"keys"`
	}{Keys: t.keys.JWKS()})
	if err != nil {
		return nil, fmt.Errorf("encode the key set: %w", err)
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}, nil
}
