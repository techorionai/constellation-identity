//go:build integration

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

const unlockPassword = "a long admin password"

// unlockEnv starts a server with an admin and sets the environment of the
// subcommand to the same database and Valkey.
func unlockEnv(t *testing.T, env *testserver.Env) *testserver.Server {
	t.Helper()
	db := env.NewDB(t)
	setEnv(t, env, db)
	var out, errOut bytes.Buffer
	if code := run([]string{"setup-link"}, &out, &errOut); code != 0 {
		t.Fatalf("setup-link: exit code = %d, stderr = %s", code, errOut.String())
	}
	srv := env.Start(t, testserver.WithDB(db))
	resp, _ := srv.NewWeb().PostForm(t, "/setup", url.Values{
		"token": {testserver.TokenOf(t, strings.TrimSpace(out.String()))}, "email": {"admin@example.com"}, "name": {"Admin"},
		"password": {unlockPassword}, "password2": {unlockPassword},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("setup: status = %d", resp.StatusCode)
	}
	return srv
}

func badLogins(t *testing.T, srv *testserver.Server, email string, n int) {
	t.Helper()
	for range n {
		srv.NewWeb().PostForm(t, "/login", url.Values{"email": {email}, "password": {"wrong password 123456"}})
	}
}

func loginStatus(t *testing.T, srv *testserver.Server, email, password string) int {
	t.Helper()
	resp, _ := srv.NewWeb().PostForm(t, "/login", url.Values{"email": {email}, "password": {password}})
	return resp.StatusCode
}

// I17, I18, I24: the subcommand unlock-login.
func TestI17_UnlockLogin(t *testing.T) {
	env := testserver.NewEnv(t)
	srv := unlockEnv(t, env)

	// I17: lock the email with 6 bad logins, then unlock with uppercase letters.
	badLogins(t, srv, "admin@example.com", 6)
	if got := loginStatus(t, srv, "admin@example.com", unlockPassword); got != http.StatusTooManyRequests {
		t.Fatalf("login of a locked email: status = %d, want 429", got)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"unlock-login", "ADMIN@Example.COM"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, errOut.String())
	}
	if strings.TrimSpace(out.String()) != "unlocked" {
		t.Fatalf("stdout = %q, want unlocked", out.String())
	}
	if strings.Contains(errOut.String(), "admin@example.com") {
		t.Fatalf("stderr has the email: %s", errOut.String())
	}
	if got := loginStatus(t, srv, "admin@example.com", unlockPassword); got != http.StatusSeeOther {
		t.Fatalf("login after the unlock: status = %d, want 303", got)
	}

	// I18: an email with no lock.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"unlock-login", "nobody@example.com"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, errOut.String())
	}
	if strings.TrimSpace(out.String()) != "not locked" {
		t.Fatalf("stdout = %q, want not locked", out.String())
	}

	// I24: a value that is not a valid email has a counter too.
	const loose = "Not An Email!"
	badLogins(t, srv, loose, 6)
	out.Reset()
	if code := run([]string{"unlock-login", loose}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, errOut.String())
	}
	if strings.TrimSpace(out.String()) != "unlocked" {
		t.Fatalf("stdout = %q, want unlocked", out.String())
	}
}

// I19: with Valkey stopped, the subcommand exits with code 1.
func TestI19_UnlockLoginValkeyDown(t *testing.T) {
	env := testserver.NewEnv(t)
	_ = unlockEnv(t, env)
	if err := env.VK.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"unlock-login", "admin@example.com"}, &out, &errOut); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q", out.String())
	}
}
