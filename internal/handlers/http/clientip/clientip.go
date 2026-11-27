// Package clientip finds the client IP address of a request and makes the key
// of a client for the rate limits.
package clientip

import (
	"net"
	"net/http"
	"net/netip"

	"github.com/techorionai/constellation-platform-go/clientinfo"
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

// CoarseBits is the prefix length of the coarse key of an IPv6 address. One
// customer often has a /48 network, so one /48 prefix is one client.
const CoarseBits = 48

// CoarseKey returns the coarse limit key of a client address. An IPv6 address
// gives its /48 prefix. An IPv4 address, an IPv4-mapped IPv6 address, and a
// value that is not an IP address give an empty string, because Key is
// already one client for them. A client with many /64 prefixes in one /48
// prefix shares the coarse key.
func CoarseKey(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	if a.Is4() {
		return ""
	}
	p, err := a.Prefix(CoarseBits)
	if err != nil {
		return ""
	}
	return p.String()
}

// Key returns the limit key of a client address. An IPv4 address gives the
// address. An IPv6 address gives its /64 prefix, because one client often has
// a whole /64 network. An IPv4-mapped IPv6 address gives the IPv4 address. A
// value that is not an IP address gives the value.
func Key(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return addr
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return a.String()
	}
	return p.String()
}
