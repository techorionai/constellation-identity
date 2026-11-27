package ipkey_test

import (
	"testing"

	"github.com/techorionai/constellation-identity/internal/domain/ipkey"
)

// U3: the keys of an IPv4 address and an IPv6 address.
func TestU3_Keys(t *testing.T) {
	cases := []struct{ in, key, coarse string }{
		{"203.0.113.5", "203.0.113.5", ""},
		{"::ffff:203.0.113.5", "203.0.113.5", ""},
		{"2001:db8:1:2::1", "2001:db8:1:2::/64", "2001:db8:1::/48"},
		{"unknown", "unknown", ""},
	}
	for _, c := range cases {
		if got := ipkey.Key(c.in); got != c.key {
			t.Errorf("Key(%q) = %q, want %q", c.in, got, c.key)
		}
		if got := ipkey.CoarseKey(c.in); got != c.coarse {
			t.Errorf("CoarseKey(%q) = %q, want %q", c.in, got, c.coarse)
		}
	}
}
