// Package clientip finds the client IP address of a request and makes the key
// of a client for the rate limits.
package clientip

import (
	"net"
	"net/netip"
	"strings"
)

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
