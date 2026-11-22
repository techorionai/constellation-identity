package domain

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ClientTypePublic is a public client. It uses the authorization code flow with
// PKCE and has no key.
const ClientTypePublic ClientType = "public"

// RedirectKind tells the use of a registered redirect URI.
type RedirectKind string

// The kinds of a redirect URI.
const (
	RedirectLogin      RedirectKind = "login"
	RedirectPostLogout RedirectKind = "post_logout"
)

func isLoopbackHost(h string) bool {
	switch strings.ToLower(h) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// isNoPortLoopback reports whether u is a registered loopback IP URI with no
// port (RFC 8252 section 7.3). It matches any port at run time. The host
// localhost does not have this exception.
func isNoPortLoopback(u *url.URL) bool {
	h := u.Hostname()
	return u.Port() == "" && (h == "127.0.0.1" || h == "::1")
}

func validHostChars(h string) bool {
	if h == "" {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}

// ValidateRedirectURI checks a registered redirect URI. The URI is absolute.
// The scheme is https, or http with a loopback host. It has no fragment, no user
// information, and no "*". The host has only letters, digits, dots, and
// hyphens, or it is an IPv6 literal in brackets, because the service puts the
// origin of the URI into the CSP header.
func ValidateRedirectURI(raw string) error {
	if raw == "" || strings.ContainsAny(raw, "*# \t\r\n\\") {
		return errors.New("the URI is empty, or it has a fragment, a space, a backslash, or a star")
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return errors.New("the URI has a control character")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "" {
		return errors.New("the URI is not an absolute URL")
	}
	if u.User != nil || u.Fragment != "" {
		return errors.New("the URI has user information or a fragment")
	}
	host := u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is6() || strings.Contains(host, "%") {
			return errors.New("the host is not a valid IPv6 literal")
		}
	} else if !validHostChars(host) {
		return errors.New("the host has a character that is not allowed")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return errors.New("the port is not valid")
		}
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(host) {
			return errors.New("the scheme http is allowed for localhost, 127.0.0.1, and [::1] only")
		}
	default:
		return errors.New("the scheme must be https")
	}
	return nil
}

// CheckRedirectURIs checks a list of redirect URIs. field is the name of the
// field of the API. It returns one problem for each URI that is not valid.
func CheckRedirectURIs(field string, uris []string) []FieldError {
	var out []FieldError
	seen := map[string]bool{}
	for i, s := range uris {
		f := field + "[" + strconv.Itoa(i) + "]"
		if err := ValidateRedirectURI(s); err != nil {
			out = append(out, FieldError{Code: "invalid_redirect_uri", Field: f, Message: err.Error()})
			continue
		}
		if seen[s] {
			out = append(out, FieldError{Code: "invalid_redirect_uri", Field: f, Message: "the URI is used two times"})
		}
		seen[s] = true
	}
	return out
}

// MatchRedirectURI reports whether requested matches one registered URI. The
// scheme, the host, the port, the path, and the query must be equal. The host
// comparison ignores the case. A trailing slash is a difference. A registered
// loopback IP URI with no port matches any port.
func MatchRedirectURI(registered []string, requested string) bool {
	if requested == "" || strings.ContainsAny(requested, "#\\") {
		return false
	}
	req, err := url.Parse(requested)
	if err != nil || !req.IsAbs() || req.User != nil || req.Fragment != "" || req.Opaque != "" {
		return false
	}
	for _, r := range registered {
		reg, err := url.Parse(r)
		if err != nil {
			continue
		}
		if reg.Scheme != req.Scheme || !strings.EqualFold(reg.Hostname(), req.Hostname()) {
			continue
		}
		if reg.EscapedPath() != req.EscapedPath() || reg.RawQuery != req.RawQuery {
			continue
		}
		if reg.Port() == req.Port() || isNoPortLoopback(reg) {
			return true
		}
	}
	return false
}

// RedirectOrigin returns the origin (scheme, host, and port) of a redirect
// URI that MatchRedirectURI accepted. It is for the CSP form-action.
func RedirectOrigin(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), true
}

func normalizedPort(u *url.URL) string {
	p := u.Port()
	switch {
	case p == "" && u.Scheme == "https", p == "443" && u.Scheme == "https":
		return "443"
	case p == "" && u.Scheme == "http", p == "80" && u.Scheme == "http":
		return "80"
	}
	return p
}

// OriginAllowed reports whether the CORS origin matches the origin of one
// registered login redirect URI. For a registered loopback IP URI with no
// port, the scheme and the host must be equal, with any port. For all other
// URIs the port must be equal too.
func OriginAllowed(registered []string, origin string) bool {
	o, err := url.Parse(origin)
	if err != nil || o.Scheme == "" || o.Host == "" || o.Path != "" || o.RawQuery != "" || o.User != nil {
		return false
	}
	for _, r := range registered {
		reg, err := url.Parse(r)
		if err != nil || reg.Scheme != o.Scheme || !strings.EqualFold(reg.Hostname(), o.Hostname()) {
			continue
		}
		if isNoPortLoopback(reg) || normalizedPort(reg) == normalizedPort(o) {
			return true
		}
	}
	return false
}
