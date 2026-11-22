package pages_test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
)

func newRequest(method, target string, body io.Reader) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), method, target, body)
}

// U6d: the client IP.
func TestU6d_ClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name    string
		remote  string
		xff     []string
		trusted []netip.Prefix
		want    string
	}{
		{"remote not trusted ignores the header", "203.0.113.5:4000", []string{"1.2.3.4"}, trusted, "203.0.113.5"},
		{"trusted proxy uses the last untrusted address", "10.0.0.1:4000", []string{"1.2.3.4, 10.0.0.2"}, trusted, "1.2.3.4"},
		{"a client cannot add an address in front", "10.0.0.1:4000", []string{"9.9.9.9, 1.2.3.4, 10.0.0.2"}, trusted, "1.2.3.4"},
		{"two header lines", "10.0.0.1:4000", []string{"9.9.9.9", "1.2.3.4, 10.0.0.2"}, trusted, "1.2.3.4"},
		{"all trusted gives the remote", "10.0.0.1:4000", []string{"10.0.0.3, 10.0.0.2"}, trusted, "10.0.0.1"},
		{"bad value gives the remote", "10.0.0.1:4000", []string{"not-an-ip"}, trusted, "10.0.0.1"},
		{"no proxies", "10.0.0.1:4000", []string{"1.2.3.4"}, nil, "10.0.0.1"},
		{"IPv6", "[2001:db8::1]:4000", nil, trusted, "2001:db8::1"},
	}
	for _, c := range cases {
		if got := pages.ClientIP(c.remote, c.xff, c.trusted); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// U9: each page sends the security headers.
func TestU9_Headers(t *testing.T) {
	h, err := pages.New(pages.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	routes := h.Routes()
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/login"},
		{http.MethodGet, "/assets/pages.css"},
		{http.MethodPost, "/login"}, // 403 from the cross origin check
		{http.MethodGet, "/nothing"},
	} {
		req := newRequest(tc.method, tc.path, nil)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		hd := rec.Header()
		csp := hd.Get("Content-Security-Policy")
		if csp != "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" {
			t.Errorf("%s %s: CSP = %q", tc.method, tc.path, csp)
		}
		if hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s: headers = %v", tc.method, tc.path, hd)
		}
	}
	req := newRequest(http.MethodPost, "/login", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST = %d, want 403", rec.Code)
	}
}

// U9a: the HSTS header is set over https only. A local http use gets none.
func TestU9a_StrictTransportSecurity(t *testing.T) {
	for _, tc := range []struct {
		name, issuer string
		tls          bool
		want         string
	}{
		{"https issuer", "https://id.example.com", false, "max-age=31536000"},
		{"TLS request with an http issuer", "http://localhost:8080", true, "max-age=31536000"},
		{"http issuer and plain request", "http://localhost:8080", false, ""},
		{"no issuer and plain request", "", false, ""},
	} {
		h, err := pages.New(pages.Deps{Issuer: tc.issuer})
		if err != nil {
			t.Fatal(err)
		}
		req := newRequest(http.MethodGet, "/login", nil)
		if tc.tls {
			req.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		h.Routes().ServeHTTP(rec, req)
		if got := rec.Header().Get("Strict-Transport-Security"); got != tc.want {
			t.Errorf("%s: Strict-Transport-Security = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestLoginFormEscapesReturnTo(t *testing.T) {
	h, _ := pages.New(pages.Deps{})
	req := newRequest(http.MethodGet, `/login?return_to=/a%22%3E%3Cscript%3E`, nil)
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("the page must escape the value: %s", rec.Body.String())
	}
}

// U10: the token query value is not in the logged URL.
func TestU10_RedactQuery(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // G101: test values, not credentials.
		"token=abc":              "token=REDACTED",
		"a=1&token=abc&b=2":      "a=1&token=REDACTED&b=2",
		"token=abc&token=def":    "token=REDACTED&token=REDACTED",
		"%74oken=abc":            "%74oken=REDACTED",
		"mytoken=abc&notoken=1":  "mytoken=abc&notoken=1",
		"":                       "",
		"return_to=%2Fa%3Fb%3Dc": "return_to=%2Fa%3Fb%3Dc",
	}
	for in, want := range cases {
		if got := pages.RedactQuery(in); got != want {
			t.Errorf("RedactQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactTokenMiddleware(t *testing.T) {
	var seenURL, seenURI, seenToken string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenURL, seenURI, seenToken = r.URL.String(), r.RequestURI, pages.TokenFromRequest(r)
	})
	req := newRequest(http.MethodGet, "/setup?token=abc&x=1", nil)
	pages.RedactToken(next).ServeHTTP(httptest.NewRecorder(), req)
	if seenURL != "/setup?token=REDACTED&x=1" || seenURI != "/setup?token=REDACTED&x=1" {
		t.Fatalf("url = %q, uri = %q", seenURL, seenURI)
	}
	if seenToken != "abc" {
		t.Fatalf("token = %q", seenToken)
	}
	if req.URL.RawQuery != "token=abc&x=1" {
		t.Fatal("the middleware must not change the original request")
	}
}

// Issue4_U10: the scrubbing of the query.
func TestIssue4_U10_Scrubbing(t *testing.T) {
	got := pages.RedactQuery("code=abc&state=s1&nonce=n&code_verifier=v&refresh_token=r&id_token_hint=h&authRequest=a&token=t&client_id=demo-ui&scope=openid")
	for _, secret := range []string{"abc", "s1", "=n&", "=v&", "=r&", "=h&", "=a&", "=t&"} {
		if strings.Contains(got, secret) {
			t.Errorf("the query still has %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "client_id=demo-ui") || !strings.Contains(got, "scope=openid") {
		t.Errorf("the other values must stay: %s", got)
	}
	if loc := pages.RedactURL("https://demo.example.com/cb?code=abc&state=s1"); loc != "https://demo.example.com/cb?code=REDACTED&state=REDACTED" {
		t.Errorf("Location = %s", loc)
	}
	// The handler behind the middleware that restores the query gets the real values.
	var seen string
	h := pages.RedactToken(pages.RestoreQuery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Query().Get("state") + "|" + r.URL.Query().Get("nonce")
	})))
	var tracing string
	outer := pages.RedactToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracing = r.URL.RawQuery
		pages.RestoreQuery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.URL.Query().Get("state") + "|" + r.URL.Query().Get("nonce")
		})).ServeHTTP(w, r)
	}))
	outer.ServeHTTP(httptest.NewRecorder(), newRequest(http.MethodGet, "/oauth/authorize?state=real-state&nonce=real-nonce", nil))
	if seen != "real-state|real-nonce" || strings.Contains(tracing, "real-") {
		t.Fatalf("handler saw %q, tracing saw %q", seen, tracing)
	}
	_ = h
}
