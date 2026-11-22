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

// ContentSecurityPolicyWithFormAction returns the policy of a page with one
// more origin in form-action. The origin comes from a registered redirect URI
// that passed the host rules of domain.ValidateRedirectURI, so it cannot add a
// directive.
func ContentSecurityPolicyWithFormAction(origin string) string {
	return strings.Replace(contentSecurityPolicy, "form-action 'self'", "form-action 'self' "+origin, 1)
}

// strictTransportSecurity is the HSTS value. It has no includeSubDomains and no
// preload, so it affects this host only.
const strictTransportSecurity = "max-age=31536000"

// SecurityHeaders adds the security headers of the pages to each response. The
// header Strict-Transport-Security is set only if the request has TLS or the
// issuer URL has the scheme https. A local http use gets no HSTS header.
func SecurityHeaders(issuer string, next http.Handler) http.Handler {
	issuerHTTPS := false
	if u, err := url.Parse(issuer); err == nil {
		issuerHTTPS = strings.EqualFold(u.Scheme, "https")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if r.TLS != nil || issuerHTTPS {
			h.Set("Strict-Transport-Security", strictTransportSecurity)
		}
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// redacted replaces the value of a secret query parameter.
const redacted = "REDACTED"

type tokenKey struct{}

type rawQueryKey struct{}

// redactedParams are the query parameters whose values never reach a log or a
// span: the one-time token, the code flow values, and the hint.
var redactedParams = map[string]bool{
	"token": true, "code": true, "code_verifier": true, "refresh_token": true,
	"id_token_hint": true, "authRequest": true, "state": true, "nonce": true,
}

// RedactQuery returns the raw query with the value of each secret parameter
// replaced by REDACTED. The other parameters stay as they are.
func RedactQuery(raw string) string {
	if raw == "" {
		return raw
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		name, _, _ := strings.Cut(p, "=")
		if n, err := url.QueryUnescape(name); err == nil && redactedParams[n] {
			parts[i] = name + "=" + redacted
		}
	}
	return strings.Join(parts, "&")
}

// RedactURL returns a URL, for example a Location header, with the secret
// query values replaced by REDACTED.
func RedactURL(raw string) string {
	base, query, ok := strings.Cut(raw, "?")
	if !ok {
		return raw
	}
	return base + "?" + RedactQuery(query)
}

// RedactToken hides the secret query parameters from everything behind it that
// logs or traces the URL. The setup link and the invite link carry a secret in
// the query, and so do the authorization request and the redirect with a code.
// It keeps the real query in the request context. Put this middleware outside
// the tracing handler, and RestoreQuery inside it.
func RedactToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "" {
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), tokenKey{}, r.URL.Query().Get("token"))
		ctx = context.WithValue(ctx, rawQueryKey{}, r.URL.RawQuery)
		r2 := r.Clone(ctx)
		r2.URL.RawQuery = RedactQuery(r.URL.RawQuery)
		if r.RequestURI != "" {
			path, _, _ := strings.Cut(r.RequestURI, "?")
			r2.RequestURI = path + "?" + r2.URL.RawQuery
		}
		next.ServeHTTP(w, r2)
	})
}

// RestoreQuery puts the real query back for the router, after the tracing
// handler and the request ID middleware saw the redacted query. The handlers
// read their own query values from the restored query.
func RestoreQuery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := r.Context().Value(rawQueryKey{}).(string)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.RawQuery = raw
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
