//go:build integration

package main

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

// setEnv sets the environment variables that config.Load reads, from the
// config of a test server.
func setEnv(t *testing.T, env *testserver.Env, db testserver.DB) {
	t.Helper()
	cfg := env.Config(t, testserver.WithDB(db))
	t.Setenv("IDENTITY_ISSUER", cfg.Issuer)
	t.Setenv("IDENTITY_DATABASE__URL", string(cfg.Database.URL))
	t.Setenv("IDENTITY_DATABASE__NAME", cfg.Database.Database)
	t.Setenv("IDENTITY_VALKEY__ADDRESS", cfg.Valkey.Address)
	t.Setenv("IDENTITY_VALKEY__USERNAME", cfg.Valkey.Username)
	t.Setenv("IDENTITY_VALKEY__PASSWORD", string(cfg.Valkey.Password))
	t.Setenv("IDENTITY_VALKEY__KEY_PREFIX", cfg.Valkey.KeyPrefix)
	t.Setenv("IDENTITY_SECRETS__MASTER_KEY", string(cfg.Secrets.MasterKey))
	t.Setenv("IDENTITY_SECRETS__MASTER_KEY_ID", cfg.Secrets.MasterKeyID)
}

// I2a and I2b: the subcommand setup-link prints a link to standard output
// before the setup, and exits with code 1 after the setup.
func TestI2_SetupLinkSubcommand(t *testing.T) {
	env := testserver.NewEnv(t)
	db := env.NewDB(t)
	setEnv(t, env, db)

	var out, errOut bytes.Buffer
	if code := run([]string{"setup-link"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, errOut.String())
	}
	first := strings.TrimSpace(out.String())
	if !strings.Contains(first, "/setup?token=") || strings.Contains(errOut.String(), testserver.TokenOf(t, first)) {
		t.Fatalf("stdout = %q, stderr = %q", first, errOut.String())
	}
	out.Reset()
	if code := run([]string{"setup-link"}, &out, &errOut); code != 0 {
		t.Fatalf("second run: exit code = %d", code)
	}
	second := strings.TrimSpace(out.String())

	srv := env.Start(t, testserver.WithDB(db))
	web := srv.NewWeb()
	resp, _ := web.Get(t, first)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("the old link: status = %d, want 400", resp.StatusCode)
	}
	resp, _ = web.PostForm(t, "/setup", url.Values{
		"token": {testserver.TokenOf(t, second)}, "email": {"admin@example.com"}, "name": {"Admin"},
		"password": {"a long admin password"}, "password2": {"a long admin password"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("the new link: status = %d, want 303", resp.StatusCode)
	}

	out.Reset()
	errOut.Reset()
	if code := run([]string{"setup-link"}, &out, &errOut); code != 1 {
		t.Fatalf("after the setup: exit code = %d, want 1", code)
	}
	if out.Len() != 0 || !strings.Contains(errOut.String(), "active admin") {
		t.Fatalf("stdout = %q, stderr = %q", out.String(), errOut.String())
	}
}
