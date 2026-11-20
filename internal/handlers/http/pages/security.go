package pages

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// contentSecurityPolicy is the policy of every page. The pages have no
// JavaScript and no inline style.
const contentSecurityPolicy = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// SecurityHeaders adds the security headers of the pages to each response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// redacted replaces the value of the query parameter token.
const redacted = "REDACTED"

type tokenKey struct{}

// RedactQuery returns the raw query with the value of each token parameter
// replaced by REDACTED. The other parameters stay as they are.
func RedactQuery(raw string) string {
	if raw == "" {
		return raw
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		name, _, _ := strings.Cut(p, "=")
		if n, err := url.QueryUnescape(name); err == nil && n == "token" {
			parts[i] = name + "=" + redacted
		}
	}
	return strings.Join(parts, "&")
}

// RedactToken hides the token query parameter from everything behind it that
// logs or traces the URL. The setup link and the invite link carry a secret
// there. The handler reads the real value with TokenFromRequest. Put this
// middleware outside the tracing handler.
func RedactToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "token") {
			next.ServeHTTP(w, r)
			return
		}
		token := r.URL.Query().Get("token")
		r2 := r.Clone(context.WithValue(r.Context(), tokenKey{}, token))
		r2.URL.RawQuery = RedactQuery(r.URL.RawQuery)
		if r.RequestURI != "" {
			path, _, _ := strings.Cut(r.RequestURI, "?")
			r2.RequestURI = path + "?" + r2.URL.RawQuery
		}
		next.ServeHTTP(w, r2)
	})
}

// TokenFromRequest returns the token query parameter of a request. It uses the
// value that RedactToken saved, and the query otherwise.
func TokenFromRequest(r *http.Request) string {
	if v, ok := r.Context().Value(tokenKey{}).(string); ok {
		return v
	}
	return r.URL.Query().Get("token")
}

// ClientIP returns the client IP of a request. It is the remote address. If the
// remote address is in a trusted proxy range, it is the last address of
// X-Forwarded-For that is not in a trusted range. A value that is not an IP
// address gives the remote address.
func ClientIP(remoteAddr string, forwardedFor []string, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	remote = remote.Unmap()
	if !isTrusted(remote, trusted) {
		return remote.String()
	}
	var chain []string
	for _, v := range forwardedFor {
		chain = append(chain, strings.Split(v, ",")...)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil {
			return remote.String()
		}
		a = a.Unmap()
		if !isTrusted(a, trusted) {
			return a.String()
		}
	}
	return remote.String()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
