package clientip_test

import (
	"net/netip"
	"testing"

	"github.com/techorionai/constellation-identity/internal/handlers/http/clientip"
)

// U2: the client IP.
func TestU2_ClientIP(t *testing.T) {
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
		if got := clientip.ClientIP(c.remote, c.xff, c.trusted); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// U1: the limit key of a client address.
func TestU1_Key(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"IPv4", "203.0.113.5", "203.0.113.5"},
		{"IPv6 first", "2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"IPv6 second in the same /64", "2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"},
		{"IPv6 other /64", "2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"IPv4-mapped IPv6", "::ffff:203.0.113.5", "203.0.113.5"},
		{"not an address", "unknown", "unknown"},
	}
	for _, c := range cases {
		if got := clientip.Key(c.in); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// R11: the coarse key of an IPv6 address is its /48 prefix. An IPv4 address
// has none. Addresses in different /64 prefixes of one /56 share it.
func TestR11_CoarseKey(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"IPv4", "203.0.113.5", ""},
		{"IPv4-mapped IPv6", "::ffff:203.0.113.5", ""},
		{"not an address", "unknown", ""},
		{"IPv6", "2001:db8:1:2::1", "2001:db8:1::/48"},
		{"other /64 of the same /48", "2001:db8:1:ff::1", "2001:db8:1::/48"},
		{"other /48", "2001:db8:2:2::1", "2001:db8:2::/48"},
	}
	for _, c := range cases {
		if got := clientip.CoarseKey(c.in); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// The 256 /64 prefixes of one /56 have 256 keys and one coarse key.
	keys, coarse := map[string]bool{}, map[string]bool{}
	for i := range 256 {
		addr := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, byte(i), 0, 0, 0, 0, 0, 0, 0, 1}).String()
		keys[clientip.Key(addr)] = true
		coarse[clientip.CoarseKey(addr)] = true
	}
	if len(keys) != 256 || len(coarse) != 1 {
		t.Fatalf("keys = %d, coarse keys = %d, want 256 and 1", len(keys), len(coarse))
	}
}

// R13: the client IP is safe only if each trusted proxy appends the address of
// its peer. A proxy that sends the header of the client unchanged lets the
// client choose its IP.
func TestR13_ProxyMustAppendPeerAddress(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	const proxy, client, forged = "10.0.0.1:4000", "203.0.113.5", "198.51.100.7"
	// The proxy appends the peer address: the forged value stays in front.
	if got := clientip.ClientIP(proxy, []string{forged + ", " + client}, trusted); got != client {
		t.Errorf("appending proxy: got %q, want %q", got, client)
	}
	// The proxy sends the header of the client unchanged: the client wins.
	if got := clientip.ClientIP(proxy, []string{forged}, trusted); got != forged {
		t.Errorf("unchanged header: got %q, want %q", got, forged)
	}
}
