//go:build integration

package services_test

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/techorionai/constellation-platform-go/resources/test/containers"
	"github.com/techorionai/constellation-platform-go/retention"

	"github.com/techorionai/constellation-identity/internal/adapters/postgres"
	"github.com/techorionai/constellation-identity/migrations"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

// applyMigrations runs the up files with the numbers from..to in order.
func applyMigrations(t *testing.T, pool *pgxpool.Pool, from, to int) {
	t.Helper()
	entries, err := migrations.Files.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		var n int
		if _, err := fmt.Sscanf(e.Name(), "%04d_", &n); err == nil && n >= from && n <= to && strings.HasSuffix(e.Name(), ".up.sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		b, err := migrations.Files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(b)); err != nil {
			t.Fatalf("migration %s: %v", name, err)
		}
	}
}

// I20: the migrations 0007 to 0009 are safe for the old version of the service.
func TestIssue4MigrationIntegration(t *testing.T) {
	env := testserver.NewEnv(t)
	u, _ := env.PG.NewDatabase(t)
	pool, err := pgxpool.New(ctx, string(u))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrations(t, pool, 1, 6)
	const userID = "00000000-0000-4000-8000-0000000000aa"
	insertOld := func(id, hash string) {
		t.Helper()
		// The old version of the service inserts a session with no auth_time.
		if _, err := pool.Exec(ctx, `INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at)
			VALUES ($1, $2, $3, now() - interval '2 hours', now(), now() + interval '1 hour', now() + interval '1 day')`, id, userID, hash); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, name, status, created_at, updated_at) VALUES ($1, 'm@example.com', 'M', 'active', now(), now())`, userID); err != nil {
		t.Fatal(err)
	}
	insertOld("00000000-0000-4000-8000-0000000000b1", "old-1")
	applyMigrations(t, pool, 7, 9)
	var same bool
	if err := pool.QueryRow(ctx, `SELECT auth_time = created_at FROM sessions WHERE id = '00000000-0000-4000-8000-0000000000b1'`).Scan(&same); err != nil || !same {
		t.Fatalf("auth_time of the old session: %v %v", same, err)
	}
	insertOld("00000000-0000-4000-8000-0000000000b2", "old-2")
	var notNull bool
	if err := pool.QueryRow(ctx, `SELECT auth_time IS NOT NULL FROM sessions WHERE id = '00000000-0000-4000-8000-0000000000b2'`).Scan(&notNull); err != nil || !notNull {
		t.Fatalf("auth_time of the new insert: %v %v", notNull, err)
	}
	// The old SQL of the sessions, the users, and the clients works.
	for _, q := range []string{
		`SELECT id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at, revoked_at, user_agent, ip_address FROM sessions WHERE token_hash = 'old-1'`,
		`UPDATE sessions SET revoked_at = now() WHERE token_hash = 'old-2'`,
		`SELECT id, email, name, status, password_hash FROM users WHERE id = '` + userID + `'`,
		`INSERT INTO clients (id, type, app, name, disabled, source, created_at, updated_at) VALUES ('svc', 'service', 'demo', 'S', false, 'config', now(), now())`,
		`DELETE FROM sessions WHERE token_hash = 'old-1'`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("old SQL: %v\n%s", err, q)
		}
	}
}

// I21, I21a: the purgers of the refresh tokens and the families.
func TestIssue4RetentionIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h)
	pool := f.a.Pool(t)
	const userID = "00000000-0000-4000-8000-0000000000aa"
	stmts := []string{
		`INSERT INTO users (id, email, name, status, created_at, updated_at) VALUES ('` + userID + `', 'ret@example.com', 'Ret', 'active', now(), now())`,
		// An old ended session and a young one, each with a family and tokens.
		`INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at) VALUES
			('00000000-0000-4000-8000-0000000000b1', '` + userID + `', 'ret-old', now() - interval '12 days', now() - interval '12 days', now() - interval '11 days', now() - interval '10 days')`,
		`INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at) VALUES
			('00000000-0000-4000-8000-0000000000b2', '` + userID + `', 'ret-young', now(), now(), now() + interval '1 hour', now() + interval '1 day')`,
		`INSERT INTO refresh_token_families (id, session_id, client_id, user_id, scope, created_at, revoked_at) VALUES
			('00000000-0000-4000-8000-0000000000c1', '00000000-0000-4000-8000-0000000000b1', 'demo-ui', '` + userID + `', 'demo:ticket:read', now() - interval '12 days', now() - interval '10 days')`,
		`INSERT INTO refresh_token_families (id, session_id, client_id, user_id, scope, created_at, revoked_at) VALUES
			('00000000-0000-4000-8000-0000000000c2', '00000000-0000-4000-8000-0000000000b2', 'demo-ui', '` + userID + `', 'demo:ticket:read', now(), NULL)`,
		`INSERT INTO refresh_token_families (id, session_id, client_id, user_id, scope, created_at, revoked_at) VALUES
			('00000000-0000-4000-8000-0000000000c3', '00000000-0000-4000-8000-0000000000b2', 'demo-ui', '` + userID + `', 'demo:ticket:read', now(), now() - interval '9 days')`,
		`INSERT INTO refresh_tokens (token_hash, family_id, created_at, used_at, expires_at) VALUES
			('t-old-expired', '00000000-0000-4000-8000-0000000000c2', now() - interval '12 days', NULL, now() - interval '10 days'),
			('t-old-used', '00000000-0000-4000-8000-0000000000c2', now() - interval '12 days', now() - interval '9 days', now() + interval '1 day'),
			('t-young', '00000000-0000-4000-8000-0000000000c2', now(), NULL, now() + interval '1 day'),
			('t-of-old-family', '00000000-0000-4000-8000-0000000000c1', now(), NULL, now() + interval '1 day')`,
	}
	for _, q := range stmts {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	params := retention.PurgeParams{Before: time.Now().Add(-7 * 24 * time.Hour), Limit: 100}
	n, err := postgres.NewRefreshTokenPurger(pool).Purge(ctx, params)
	if err != nil || n != 2 {
		t.Fatalf("token purge: %d %v", n, err)
	}
	if f.countWhere(`SELECT count(*) FROM refresh_tokens WHERE token_hash IN ('t-young', 't-of-old-family')`) != 2 {
		t.Fatal("young tokens must stay")
	}
	n, err = postgres.NewRefreshFamilyPurger(pool).Purge(ctx, params)
	if err != nil || n != 2 {
		t.Fatalf("family purge: %d %v", n, err)
	}
	if f.countWhere(`SELECT count(*) FROM refresh_token_families WHERE id = '00000000-0000-4000-8000-0000000000c2'`) != 1 {
		t.Fatal("the young family must stay")
	}
	if f.countWhere(`SELECT count(*) FROM refresh_tokens WHERE token_hash = 't-of-old-family'`) != 0 {
		t.Fatal("the tokens of a deleted family go with it")
	}
	// I21a: the sessions purger deletes an ended session that has a family.
	if _, err := pool.Exec(ctx, `INSERT INTO refresh_token_families (id, session_id, client_id, user_id, scope, created_at)
		VALUES ('00000000-0000-4000-8000-0000000000c4', '00000000-0000-4000-8000-0000000000b1', 'demo-ui', $1, 'demo:ticket:read', now())`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO refresh_tokens (token_hash, family_id, created_at, expires_at)
		VALUES ('t-last', '00000000-0000-4000-8000-0000000000c4', now(), now() + interval '1 day')`); err != nil {
		t.Fatal(err)
	}
	if n, err := postgres.NewSessionPurger(pool).Purge(ctx, params); err != nil || n != 1 {
		t.Fatalf("session purge: %d %v", n, err)
	}
	if f.countWhere(`SELECT count(*) FROM refresh_token_families WHERE id = '00000000-0000-4000-8000-0000000000c4'`) != 0 ||
		f.countWhere(`SELECT count(*) FROM refresh_tokens WHERE token_hash = 't-last'`) != 0 {
		t.Fatal("the family and the token of the deleted session must go")
	}
}

// I17 and I27: no secret in a log or a span, and the reuse counters.
func TestIssue4TelemetryIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h)
	admin := f.adminToken(adminScopes)
	f.newUser(admin, "agent@example.com", userPass2, "demo:agent")

	codeBefore := counterValue(t, "identity.code.reuse")
	web := f.a.NewWeb()
	p := testserver.NewPKCE(t)
	resp := web.Authorize(t, testserver.AuthorizeQuery("demo-ui", demoRedirect, demoScope, p, map[string]string{"state": "state-secret-1", "nonce": "nonce-secret-1"}))
	authRequest := testserver.Location(t, resp).Query().Get("authRequest")
	h.ledger.add(&h.ledger.flow, authRequest)
	resp, _ = web.PostForm(t, "/login", url.Values{"email": {"agent@example.com"}, "password": {userPass2}, "authRequest": {authRequest}})
	resp, _ = web.Get(t, resp.Header.Get("Location"))
	code := codeOf(t, testserver.Location(t, resp))
	h.ledger.add(&h.ledger.flow, code)
	h.ledger.add(&h.ledger.flow, p.Verifier)
	_, tr := f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, p.Verifier))
	h.ledger.add(&h.ledger.flow, tr.RefreshToken)
	h.ledger.add(&h.ledger.flow, tr.IDToken)
	// Reuse of the code and of the refresh token.
	f.a.TokenRequest(t, testserver.CodeForm("demo-ui", code, demoRedirect, p.Verifier))
	if counterValue(t, "identity.code.reuse") != codeBefore+1 {
		t.Fatal("identity.code.reuse must rise by 1")
	}
	tr2, _ := f.login("agent@example.com", userPass2, "demo-ui", demoRedirect, demoScope)
	_, second := f.refresh("demo-ui", tr2.RefreshToken)
	f.refresh("demo-ui", tr2.RefreshToken)
	h.ledger.add(&h.ledger.flow, second.RefreshToken)
	web.Get(t, "/oauth/end_session?"+url.Values{"id_token_hint": {tr.IDToken}}.Encode())
	resp2, _ := f.a.Post(t, "/oauth/revoke", url.Values{"token": {tr2.RefreshToken}, "client_id": {"demo-ui"}}.Encode())
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", resp2.StatusCode)
	}

	var texts []string
	for _, l := range h.ledger.logs {
		texts = append(texts, l.Text())
	}
	spans := ""
	for _, s := range spanExporter.GetSpans() {
		spans += s.Name + "\n"
		for _, a := range s.Attributes {
			spans += string(a.Key) + "=" + a.Value.String() + "\n"
		}
		for _, e := range s.Events {
			for _, a := range e.Attributes {
				spans += string(a.Key) + "=" + a.Value.String() + "\n"
			}
		}
	}
	if len(h.ledger.flow) < 6 {
		t.Fatal("the ledger has too few values")
	}
	secrets := append(append([]string{}, h.ledger.flow...), "state-secret-1", "nonce-secret-1")
	for _, secret := range secrets {
		for _, text := range texts {
			if strings.Contains(text, secret) {
				t.Fatalf("a log record holds the secret %q", secret[:6])
			}
		}
		if strings.Contains(spans, secret) {
			t.Fatalf("a span holds the secret %q", secret[:6])
		}
	}
}

// I3i: a Valkey fault gives 503 and no token. The service revokes nothing.
func TestIssue4ValkeyDownIntegration(t *testing.T) {
	observability()
	base := testserver.NewEnv(t)
	vk := containers.Valkey(t, containers.WithValkeyImage(testserver.ValkeyImage))
	h := &harness{env: &testserver.Env{PG: base.PG, VK: vk}, ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	f := newFixture(t, h)
	p := testserver.NewPKCE(t)
	code := codeOf(t, f.admin.CodeFlow(t, testserver.AuthorizeQuery("admin-ui", adminRedirect, "openid identity:user:read", p, nil), "admin@example.com", adminPassword))
	sid := f.sessionID(f.admin)
	if err := vk.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	resp, tr := f.a.TokenRequest(t, testserver.CodeForm("admin-ui", code, adminRedirect, p.Verifier))
	if resp.StatusCode != http.StatusServiceUnavailable || tr.Error != "temporarily_unavailable" || tr.AccessToken != "" {
		t.Fatalf("token request with Valkey down: %d %+v", resp.StatusCode, tr)
	}
	if f.countWhere(`SELECT count(*) FROM sessions WHERE id = $1 AND revoked_at IS NULL`, sid) != 1 || f.countWhere(`SELECT count(*) FROM refresh_token_families`) != 0 {
		t.Fatal("no session and no family may change")
	}
	// A new authorization request cannot store its state.
	resp = f.admin.Authorize(t, testserver.AuthorizeQuery("admin-ui", adminRedirect, "openid identity:user:read", p, map[string]string{"prompt": "login"}))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("authorize with Valkey down: %d", resp.StatusCode)
	}
}
