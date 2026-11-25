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
