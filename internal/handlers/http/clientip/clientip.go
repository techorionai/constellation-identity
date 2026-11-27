// Package clientip finds the client IP address of a request and makes the key
// of a client for the rate limits.
package clientip

import (
	"net"
	"net/http"
	"net/netip"

	"github.com/techorionai/constellation-platform-go/clientinfo"

	"github.com/techorionai/constellation-identity/internal/domain/ipkey"
)

// FromRequest returns the client IP of a request. It reads the value that the
// clientinfo middleware of platform-go put into the context. That middleware is
// the one place that reads X-Forwarded-For and the trusted proxies, so the rate
// limits and the audit entries use the same address. If the context has no
// valid address, the result is the remote address of the connection. This
// function never reads X-Forwarded-For.
func FromRequest(r *http.Request) string {
	if info, ok := clientinfo.FromContext(r.Context()); ok && info.IP.IsValid() {
		return info.IP.String()
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.WithZone("").Unmap().String()
	}
	return host
}

// CoarseBits is the prefix length of the coarse key of an IPv6 address.
const CoarseBits = ipkey.CoarseBits

// CoarseKey returns the coarse limit key of a client address. See ipkey.CoarseKey.
func CoarseKey(addr string) string { return ipkey.CoarseKey(addr) }

// Key returns the limit key of a client address. See ipkey.Key.
func Key(addr string) string { return ipkey.Key(addr) }
