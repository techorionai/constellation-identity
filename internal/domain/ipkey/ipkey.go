// Package ipkey makes the limit keys of a client IP address.
package ipkey

import "net/netip"

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
