package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// U11: the healthcheck gives exit code 0 for 200 and 1 for 503.
func TestU11_Healthcheck(t *testing.T) {
	for _, tt := range []struct {
		status int
		want   int
	}{{http.StatusOK, 0}, {http.StatusServiceUnavailable, 1}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/readyz" {
				t.Errorf("path = %s", r.URL.Path)
			}
			w.WriteHeader(tt.status)
		}))
		var out, errOut bytes.Buffer
		got := healthcheck(context.Background(), srv.URL+"/readyz", &out, &errOut)
		srv.Close()
		if got != tt.want {
			t.Errorf("status %d: exit = %d, want %d", tt.status, got, tt.want)
		}
	}
}

func TestHealthcheckNoServer(t *testing.T) {
	var out, errOut bytes.Buffer
	if got := healthcheck(context.Background(), "http://127.0.0.1:1/readyz", &out, &errOut); got != 1 {
		t.Fatalf("exit = %d, want 1", got)
	}
}

func TestHealthcheckUsesAdminPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	t.Setenv("IDENTITY_ADMIN__ADDR", ":"+addr[strings.LastIndex(addr, ":")+1:])
	var out, errOut bytes.Buffer
	if got := run([]string{"healthcheck"}, &out, &errOut); got != 0 {
		t.Fatalf("exit = %d, stderr %s", got, errOut.String())
	}
}

// U14: rotate-signing-keys without --force gives exit code 2 and changes nothing.
func TestU14_RotateWithoutForce(t *testing.T) {
	// No env variable is set, so a call to the database would fail with exit code 1.
	var out, errOut bytes.Buffer
	if got := run([]string{"rotate-signing-keys"}, &out, &errOut); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
	if !strings.Contains(out.String(), "--force") || !strings.Contains(out.String(), "Nothing changed") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if got := run([]string{"nope"}, &out, &errOut); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
}
