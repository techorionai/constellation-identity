package domain

import (
	"net/url"
	"strings"
)

// SafeReturnTo checks the return_to value of a login. It returns the path and
// the query to redirect to, and true if the value is safe. It accepts only a
// local path. It rejects a control character, a backslash, a scheme, a host,
// and a path that starts with "//", also after the decoding of the path.
func SafeReturnTo(raw string) (string, bool) {
	if raw == "" || hasUnsafeRune(raw) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || hasUnsafeRune(u.Path) {
		return "", false
	}
	escaped := u.EscapedPath()
	if !strings.HasPrefix(escaped, "/") || strings.HasPrefix(escaped, "//") {
		return "", false
	}
	if u.RawQuery != "" {
		return escaped + "?" + u.RawQuery, true
	}
	return escaped, true
}

func hasUnsafeRune(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0x5c {
			return true
		}
	}
	return false
}
