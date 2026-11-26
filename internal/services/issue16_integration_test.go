//go:build integration

package services_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/internal/services"
	"github.com/techorionai/constellation-identity/migrations"
	"github.com/techorionai/constellation-identity/resources/test/oidcprovider"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
	swa "github.com/techorionai/constellation-identity/resources/test/webauthn"
)

// idpOutcome returns the value of the counter identity.idp.logins for an outcome.
func idpOutcome(t *testing.T, outcome string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := metricReader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if m.Name != "identity.idp.logins" || !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				if v, ok := dp.Attributes.Value("outcome"); ok && v.AsString() == outcome {
					total += dp.Value
				}
			}
		}
	}
	return total
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// I1: migration 0014 up and down. The previous version runs on the new schema.
func TestIssue16MigrationIntegration(t *testing.T) {
	env := testserver.NewEnv(t)
	u, _ := env.PG.NewDatabase(t)
	pool, err := pgxpool.New(ctx, string(u))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrations(t, pool, 1, 13)
	const userA = "00000000-0000-4000-8000-0000000000aa"
	const userB = "00000000-0000-4000-8000-0000000000ab"
	for _, id := range []string{userA, userB} {
		if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, name, status, created_at, updated_at) VALUES ($1, $2, 'M', 'active', now(), now())`, id, id+"@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	// A token of the old version, before the migration.
	if _, err := pool.Exec(ctx, `INSERT INTO api_tokens (id, token_hash, user_id, name, scope, created_at, expires_at)
		VALUES ('00000000-0000-4000-8000-0000000000e1', 'h1', $1, 'old', 'demo:ticket:read', now(), now() + interval '1 day')`, userA); err != nil {
		t.Fatal(err)
	}
	applyMigrations(t, pool, 14, 14)
	// The SQL of the previous version works on the new schema.
	if _, err := pool.Exec(ctx, `INSERT INTO api_tokens (id, token_hash, user_id, name, scope, created_at, expires_at)
		VALUES ('00000000-0000-4000-8000-0000000000e2', 'h2', $1, 'old2', 'demo:ticket:read', now(), now() + interval '1 day')`, userA); err != nil {
		t.Fatalf("old SQL: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE amr = '{}'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("old tokens have an empty amr: %d, %v", n, err)
	}
	insert := `INSERT INTO identity_links (id, user_id, provider, subject, created_at) VALUES ($1, $2, $3, $4, now())`
	if _, err := pool.Exec(ctx, insert, "00000000-0000-4000-8000-0000000000c1", userA, "google", "s1"); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]any{
		"the account of another user": {"00000000-0000-4000-8000-0000000000c2", userB, "google", "s1"},
		"a second link of a provider": {"00000000-0000-4000-8000-0000000000c3", userA, "google", "s2"},
	} {
		if _, err := pool.Exec(ctx, insert, args...); err == nil {
			t.Fatalf("%s must fail", name)
		}
	}
	// The same subject at another provider is another account.
	if _, err := pool.Exec(ctx, insert, "00000000-0000-4000-8000-0000000000c4", userB, "microsoft", "s1"); err != nil {
		t.Fatalf("same subject, other provider: %v", err)
	}
	// A user delete removes the links.
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity_links`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("links after the user delete: %d, %v", n, err)
	}
	down, err := migrations.Files.ReadFile("0014_identity_links.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'identity_links'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tables after the down: %d, %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'api_tokens' AND column_name = 'amr'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("columns after the down: %d, %v", n, err)
	}
}

// I3: a provider with no stored secret stops the start.
func TestIssue16SecretMissingIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	p := oidcprovider.Start(t)
	logs := testserver.NewLogCapture()
	_, err := h.env.TryStart(t, testserver.WithLogger(logs.Logger()), testserver.WithMasterKey(h.masterKey, "test"),
		testserver.WithIdp(testserver.IdpSettings{Provider: p, Google: true, NoSecrets: true}))
	if err == nil || !strings.Contains(err.Error(), "client secret") {
		t.Fatalf("err = %v, want the error of a missing secret", err)
	}
	var found bool
	for _, r := range logs.Records(t) {
		if r["event"] == "identity.idp.secret_missing" && r["provider"] == "google" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no log event identity.idp.secret_missing: %s", logs.Text())
	}
}

// I18: the bucket idp. The third start of one IP gets 429.
func TestIssue16RateLimitIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	p := oidcprovider.Start(t)
	a := h.start(t, testserver.WithIdp(testserver.IdpSettings{Provider: p, Google: true}),
		testserver.WithRateLimits(map[string]ratelimit.Rule{"idp": {Limit: 2}}))
	web := a.NewWeb()
	for i, want := range []int{http.StatusFound, http.StatusFound, http.StatusTooManyRequests} {
		resp, _ := web.Get(t, "/login/oidc/google")
		if resp.StatusCode != want {
			t.Fatalf("request %d: %d, want %d", i+1, resp.StatusCode, want)
		}
	}
}

// I19, I24: the one deadline. A slow token endpoint and a slow discovery document
// give the page "The login did not complete." in a short time.
func TestIssue16TimeoutIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	p := oidcprovider.Start(t)
	a := h.start(t, testserver.WithIdp(testserver.IdpSettings{Provider: p, Google: true, HTTPTimeout: 2 * time.Second}))
	r := &idpRig{f: &fixture{t: t, a: a}, p: p}
	web := a.NewWeb()
	// I24: the discovery is slow. The start answers 502 before the timeout plus 2 s.
	p.SetDelay("discovery", 10*time.Second)
	begin := time.Now()
	resp, body := web.Get(t, "/login/oidc/google")
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "The login did not complete.") || time.Since(begin) > 4*time.Second {
		t.Fatalf("slow discovery: %d after %s: %s", resp.StatusCode, time.Since(begin), body)
	}
	if len(web.CookiesWithPrefix(pages.IdpCookieName)) != 0 {
		t.Fatal("a failed start sets no cookie")
	}
	// I19: the token endpoint is slow.
	p.SetDelay("discovery", 0)
	p.SetDelay("token", 10*time.Second)
	p.Expect(google("g-slow", "slow@example.com"))
	_, _, authURL := r.start(web, "/login/oidc/google")
	if authURL == "" {
		t.Fatal("the start must work")
	}
	begin = time.Now()
	resp, body, _ = r.finish(web, authURL)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "The login did not complete.") || time.Since(begin) > 5*time.Second {
		t.Fatalf("slow token endpoint: %d after %s: %s", resp.StatusCode, time.Since(begin), body)
	}
}

func TestIssue16Integration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	p := oidcprovider.Start(t)
	f := newFixture(t, h, mfaOptions(testserver.WithIdp(testserver.IdpSettings{Provider: p, Google: true, Microsoft: true}))...)
	r := newIdpRig(f, p)
	const demoRole = "demo:agent"
	r.track("google-client-secret", "microsoft-client-secret", "UPSTREAM-ACCESS-", "UPSTREAM-REFRESH-", "TEXT-FROM-THE-PROVIDER-")

	// I2: the client secrets are in the secrets store as envelopes.
	t.Run("I2_secrets_stored", func(t *testing.T) {
		rows, err := f.a.Pool(t).Query(ctx, `SELECT name, ciphertext FROM platform_secrets WHERE name LIKE 'identity/idp/%' ORDER BY name`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var names []string
		for rows.Next() {
			var name string
			var ct []byte
			if err := rows.Scan(&name, &ct); err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
			if strings.Contains(string(ct), "client-secret") && strings.Contains(string(ct), "google") {
				t.Fatalf("%s is not encrypted", name)
			}
		}
		if strings.Join(names, " ") != "identity/idp/google/client-secret identity/idp/microsoft/client-secret" {
			t.Fatalf("names = %v", names)
		}
		if err := services.SetIdpSecret(ctx, f.a.Config, "okta", "x", discardLog()); err == nil {
			t.Fatal("an unknown provider must fail")
		}
		if text := f.a.logs.Text(); strings.Contains(text, "google-client-secret") || strings.Contains(text, "microsoft-client-secret") {
			t.Fatal("the log holds a client secret")
		}
	})

	// I4: a user links Google on the account page. I7 and I10 follow.
	t.Run("I4_link", func(t *testing.T) {
		id, web := f.userWithPassword("i4@example.com", demoRole)
		body := f.page(web, "/account/security")
		for _, want := range []string{"Link Google", "Link Microsoft", "Set a password"} {
			if want == "Set a password" {
				if strings.Contains(body, want) {
					t.Fatalf("a user with a password needs no %q", want)
				}
				continue
			}
			if !strings.Contains(body, want) {
				t.Fatalf("the page has no %q: %s", want, body)
			}
		}
		r.link(web, "google", google("g-i4", "i4-up@example.com"))
		if f.linkCount(id) != 1 {
			t.Fatal("no link row")
		}
		body = f.page(web, "/account/security")
		if !strings.Contains(body, "Linked accounts") || !strings.Contains(body, "i4-up@example.com") || strings.Contains(body, "Link Google") || !strings.Contains(body, "Link Microsoft") {
			t.Fatalf("the page after the link: %s", body)
		}
		tr, _ := f.login("i4@example.com", userPassword, "admin-ui", adminRedirect, linkScope)
		resp, m := f.api(tr.AccessToken, http.MethodGet, "/v1/me/identity-links", nil)
		status(t, resp, http.StatusOK, "MeIdentityLinks_list")
		items, _ := m["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("list = %v", m)
		}
		item := items[0].(map[string]any)
		if item["provider"] != "google" || item["email"] != "i4-up@example.com" || item["createdAt"] == nil {
			t.Fatalf("item = %v", item)
		}
		for _, key := range []string{"subject", "sub", "id", "userId"} {
			if _, has := item[key]; has {
				t.Fatalf("the item has %s", key)
			}
		}
		if len(auditsOf(t, f.a, "identity:identity_link:add")) == 0 || len(noticesOf(t, f.a, "identity_link_added")) == 0 {
			t.Fatal("no audit entry or notice for the link")
		}
		// The flow ends with a good link: the cookie of the flow is gone.
		if len(web.CookiesWithPrefix(pages.IdpCookieName)) != 0 {
			t.Fatal("the cookie of the flow must end")
		}
	})

	// I5, I7, I8, I9, I10: the login with a link and the refusals.
	t.Run("I5_login", func(t *testing.T) {
		id, web := f.userWithPassword("i5@example.com", demoRole)
		r.link(web, "google", google("g-i5", "i5-up@example.com"))
		w2 := f.a.NewWeb()
		tr := r.fedTokens(w2, "google", google("g-i5", "i5-new@example.com"), linkScope)
		if got := amrOf(t, tr.AccessToken); got != "fed" {
			t.Fatalf("amr = %q", got)
		}
		if got := f.amrOfSession(w2); got != "fed" {
			t.Fatalf("session methods = %q", got)
		}
		var email string
		var last *time.Time
		if err := f.a.Pool(t).QueryRow(ctx, `SELECT email, last_used_at FROM identity_links WHERE user_id = $1`, id).Scan(&email, &last); err != nil || last == nil || email != "i5-new@example.com" {
			t.Fatalf("link row: %q %v %v", email, last, err)
		}
		before := idpOutcome(t, "ok")
		if before == 0 {
			t.Fatal("the counter has no ok outcome")
		}
	})

	t.Run("I7_not_linked", func(t *testing.T) {
		id, _ := f.userWithPassword("i7@example.com", demoRole)
		web := f.a.NewWeb()
		sessions := sessionCount(t, f.a.Server)
		resp, body := r.run(web, "/login/oidc/google?purpose=login", google("g-unlinked", "i7@example.com"))
		status(t, resp, http.StatusForbidden, "unlinked account")
		if !strings.Contains(string(body), "This account is not linked. Log in and link it on the account page.") {
			t.Fatalf("body = %s", body)
		}
		if web.Cookie(pages.CookieName) != "" || sessionCount(t, f.a.Server) != sessions || f.linkCount(id) != 0 {
			t.Fatal("no session and no link")
		}
		if idpOutcome(t, "not_linked") == 0 {
			t.Fatal("the counter has no not_linked outcome")
		}
	})

	t.Run("I8_state_and_binding", func(t *testing.T) {
		_, web := f.userWithPassword("i8@example.com", demoRole)
		r.link(web, "google", google("g-i8", "i8@example.com"))
		login := google("g-i8", "i8@example.com")
		// A wrong state.
		w := f.a.NewWeb()
		p.Expect(login)
		_, _, authURL := r.start(w, "/login/oidc/google")
		resp, body := w.Get(t, "/login/oidc/google/callback?code=x&state=wrong")
		status(t, resp, http.StatusBadRequest, "wrong state")
		if !strings.Contains(string(body), "The login expired. Try again.") {
			t.Fatalf("body = %s", body)
		}
		// A good callback, then the same callback again (a used state).
		resp, _, cb := r.finish(w, authURL)
		status(t, resp, http.StatusSeeOther, "good callback")
		resp, body = w.Get(t, cb.RequestURI())
		status(t, resp, http.StatusBadRequest, "used state")
		if !strings.Contains(string(body), "The login expired. Try again.") {
			t.Fatalf("body = %s", body)
		}
		// The binding cookie of another browser.
		w1, w2 := f.a.NewWeb(), f.a.NewWeb()
		p.Expect(login)
		_, _, authURL = r.start(w1, "/login/oidc/google")
		_, _, _ = r.start(w2, "/login/oidc/google")
		resp, body, _ = r.finish(w2, authURL)
		status(t, resp, http.StatusBadRequest, "cookie of another browser")
		if !strings.Contains(string(body), "The login expired. Try again.") || w2.Cookie(pages.CookieName) != "" {
			t.Fatalf("body = %s", body)
		}
		// No cookie at all.
		w3 := f.a.NewWeb()
		p.Expect(login)
		_, _, authURL = r.start(w1, "/login/oidc/google")
		resp, _, _ = r.finish(w3, authURL)
		status(t, resp, http.StatusBadRequest, "no cookie")
		if idpOutcome(t, "bad_state") < 3 {
			t.Fatal("the counter has too few bad_state outcomes")
		}
	})

	t.Run("I9_token_refusals", func(t *testing.T) {
		_, web := f.userWithPassword("i9@example.com", demoRole)
		r.link(web, "google", google("g-i9", "i9@example.com"))
		other, wrongNonce := "other-client", "wrong-nonce"
		before := idpOutcome(t, "token_invalid")
		cases := map[string]func(*oidcprovider.Login){
			"wrong nonce":    func(l *oidcprovider.Login) { l.Nonce = &wrongNonce },
			"wrong audience": func(l *oidcprovider.Login) { l.Aud = []string{"another"} },
			"azp of another": func(l *oidcprovider.Login) { l.Azp = &other },
			"two audiences":  func(l *oidcprovider.Login) { l.Aud = []string{oidcprovider.GoogleClientID, "x"} },
			"expired":        func(l *oidcprovider.Login) { l.Expired = true },
			"wrong issuer":   func(l *oidcprovider.Login) { l.Iss = "https://evil.example.com" },
		}
		for name, mod := range cases {
			l := google("g-i9", "i9@example.com")
			mod(&l)
			w := f.a.NewWeb()
			resp, body := r.run(w, "/login/oidc/google", l)
			status(t, resp, http.StatusBadRequest, name)
			if !strings.Contains(string(body), "The login did not complete.") || w.Cookie(pages.CookieName) != "" {
				t.Fatalf("%s: %s", name, body)
			}
		}
		if got := idpOutcome(t, "token_invalid") - before; got != int64(len(cases)) {
			t.Fatalf("token_invalid outcomes = %d, want %d", got, len(cases))
		}
	})

	t.Run("I10_linked_to_another_user", func(t *testing.T) {
		_, web := f.userWithPassword("i10a@example.com", demoRole)
		r.link(web, "google", google("g-i10", "i10@example.com"))
		idB, webB := f.userWithPassword("i10b@example.com", demoRole)
		resp, body := r.run(webB, r.confirmLink(webB, "google", userPassword), google("g-i10", "i10@example.com"))
		status(t, resp, http.StatusConflict, "account of another user")
		if !strings.Contains(string(body), "This account is linked to another user.") || f.linkCount(idB) != 0 {
			t.Fatalf("body = %s", body)
		}
		// A second link of the same provider for the same user.
		resp, body = r.run(web, r.confirmLink(web, "google", userPassword), google("g-i10-b", "i10@example.com"))
		status(t, resp, http.StatusConflict, "second link")
		if !strings.Contains(string(body), "You already linked a google account. Remove it first.") {
			t.Fatalf("body = %s", body)
		}
	})

	// I11, I12: the invite with an upstream account.
	t.Run("I11_invite_with_google", func(t *testing.T) {
		tok := f.adminToken(adminScopes)
		id, itoken := f.inviteUser(tok, "i11@example.com", demoRole)
		web := f.a.NewWeb()
		page := f.page(web, "/invite?token="+itoken)
		if !strings.Contains(page, "Accept with Google") || !strings.Contains(page, "Accept with Microsoft") || !strings.Contains(page, "purpose=invite") {
			t.Fatalf("invite page: %s", page)
		}
		l := google("g-i11", "I11@Example.com")
		resp, body := r.run(web, "/login/oidc/google?purpose=invite&token="+itoken, l)
		status(t, resp, http.StatusSeeOther, "invite with Google")
		if resp.Header.Get("Location") != "/login/done" || web.Cookie(pages.CookieName) == "" || f.amrOfSession(web) != "fed" {
			t.Fatalf("callback: %q %s", resp.Header.Get("Location"), body)
		}
		f.a.trackSession(web)
		if f.countWhere(`SELECT count(*) FROM users WHERE id = $1 AND status = 'active' AND password_hash IS NULL`, id) != 1 || f.linkCount(id) != 1 {
			t.Fatal("the user must be active with no password and one link")
		}
		if f.countWhere(`SELECT count(*) FROM one_time_tokens WHERE user_id = $1 AND used_at IS NOT NULL`, id) != 1 {
			t.Fatal("the token must be used")
		}
		resp, _ = f.a.NewWeb().Get(t, "/invite?token="+itoken)
		status(t, resp, http.StatusBadRequest, "the used token")
		if len(auditsOf(t, f.a, "identity:identity_link:add")) < 2 || len(noticesOf(t, f.a, "identity_link_added")) < 2 {
			t.Fatal("the invite needs an audit entry and a notice")
		}
		// The login of a user with no password: the password login does not work.
		w2 := f.a.NewWeb()
		f.a.ledger.add(&f.a.ledger.passwords, userPassword)
		resp, _ = w2.PostForm(t, "/login", url.Values{"email": {"i11@example.com"}, "password": {userPassword}})
		status(t, resp, http.StatusUnauthorized, "password login of a user with no password")
	})

	t.Run("I12_invite_mismatch", func(t *testing.T) {
		tok := f.adminToken(adminScopes)
		id, itoken := f.inviteUser(tok, "i12@example.com", demoRole)
		for name, l := range map[string]oidcprovider.Login{
			"not verified":  func() oidcprovider.Login { l := google("g-i12", "i12@example.com"); l.EmailVerified = false; return l }(),
			"another email": google("g-i12", "someone-else@example.com"),
		} {
			web := f.a.NewWeb()
			resp, body := r.run(web, "/login/oidc/google?purpose=invite&token="+itoken, l)
			status(t, resp, http.StatusForbidden, name)
			if !strings.Contains(string(body), "This account does not match the invitation.") || web.Cookie(pages.CookieName) != "" {
				t.Fatalf("%s: %s", name, body)
			}
		}
		// A Microsoft account with no xms_edov.
		web := f.a.NewWeb()
		ms := microsoft("o-i12", "i12@example.com")
		ms.XmsEdov = nil
		resp, _ := r.run(web, "/login/oidc/microsoft?purpose=invite&token="+itoken, ms)
		status(t, resp, http.StatusForbidden, "microsoft without xms_edov")
		if f.linkCount(id) != 0 || f.countWhere(`SELECT count(*) FROM users WHERE id = $1 AND status = 'invited'`, id) != 1 {
			t.Fatal("no change")
		}
		// The token still works with a password.
		f.a.ledger.add(&f.a.ledger.passwords, userPassword)
		resp, _ = f.a.NewWeb().PostForm(t, "/invite", url.Values{"token": {itoken}, "password": {userPassword}, "password2": {userPassword}})
		status(t, resp, http.StatusSeeOther, "invite with a password")
		// A Microsoft invite with the verified email works.
		id2, itoken2 := f.inviteUser(tok, "i12b@example.com", demoRole)
		web2 := f.a.NewWeb()
		resp, body := r.run(web2, "/login/oidc/microsoft?purpose=invite&token="+itoken2, microsoft("o-i12b", "i12b@example.com"))
		status(t, resp, http.StatusSeeOther, "microsoft invite")
		if f.linkCount(id2) != 1 {
			t.Fatalf("microsoft invite: %s", body)
		}
	})

	// I13, I33: Microsoft with the tenant organizations, through the service.
	t.Run("I13_I33_microsoft", func(t *testing.T) {
		id, web := f.userWithPassword("i13@example.com", demoRole)
		r.link(web, "microsoft", microsoft("o-i13", "i13@example.com"))
		var subject string
		if err := f.a.Pool(t).QueryRow(ctx, `SELECT subject FROM identity_links WHERE user_id = $1`, id).Scan(&subject); err != nil || subject != oidcprovider.TenantA+":o-i13" {
			t.Fatalf("subject = %q, %v", subject, err)
		}
		try := func(mod func(*oidcprovider.Login)) int {
			l := microsoft("o-i13", "i13@example.com")
			if mod != nil {
				mod(&l)
			}
			w := f.a.NewWeb()
			resp, _ := r.run(w, "/login/oidc/microsoft", l)
			return resp.StatusCode
		}
		if got := try(nil); got != http.StatusSeeOther {
			t.Fatalf("tenant A: %d", got)
		}
		issB := p.MicrosoftBase() + "/" + oidcprovider.TenantB + "/v2.0"
		if got := try(func(l *oidcprovider.Login) { l.Iss = issB }); got != http.StatusBadRequest {
			t.Fatalf("issuer of tenant B: %d", got)
		}
		// I33: the signing keys.
		for kind, want := range map[string]int{
			oidcprovider.KeyTemplate: http.StatusSeeOther, oidcprovider.KeyNone: http.StatusSeeOther, oidcprovider.KeyTenantB: http.StatusBadRequest,
		} {
			if got := try(func(l *oidcprovider.Login) { l.KeyKind = kind }); got != want {
				t.Errorf("key %s: %d, want %d", kind, got, want)
			}
		}
	})

	// I20, I23, I37: the failures of the provider.
	t.Run("I20_I23_I37_provider_failures", func(t *testing.T) {
		_, web := f.userWithPassword("i20@example.com", demoRole)
		r.link(web, "google", google("g-i20", "i20@example.com"))
		l := google("g-i20", "i20@example.com")
		before := idpOutcome(t, "provider_error")
		// I20: the error parameter. The page and the log have no text of the provider.
		el := l
		el.AuthError = "access_denied"
		w := f.a.NewWeb()
		resp, body := r.run(w, "/login/oidc/google", el)
		status(t, resp, http.StatusBadRequest, "error parameter")
		if !strings.Contains(string(body), "The login did not complete.") || strings.Contains(string(body), "TEXT-FROM-THE-PROVIDER") {
			t.Fatalf("body = %s", body)
		}
		if strings.Contains(f.a.logs.Text(), "TEXT-FROM-THE-PROVIDER") || strings.Contains(spansText(), "TEXT-FROM-THE-PROVIDER") {
			t.Fatal("the text of the provider is in a log record or a span")
		}
		// I23: a wrong client secret, and a refusal of the token endpoint.
		p.SetSecret("google", "another-secret")
		resp, _ = r.run(f.a.NewWeb(), "/login/oidc/google", l)
		status(t, resp, http.StatusBadRequest, "wrong client secret")
		p.SetSecret("google", oidcprovider.GoogleSecret)
		tl := l
		tl.TokenError = "invalid_grant"
		resp, _ = r.run(f.a.NewWeb(), "/login/oidc/google", tl)
		status(t, resp, http.StatusBadRequest, "token endpoint refuses")
		// I37: the iss parameter.
		for name, mod := range map[string]func(*oidcprovider.Login){
			"missing iss": func(l *oidcprovider.Login) { l.OmitIss = true },
			"wrong iss":   func(l *oidcprovider.Login) { l.IssParam = "https://evil.example.com" },
		} {
			x := l
			mod(&x)
			resp, body := r.run(f.a.NewWeb(), "/login/oidc/google", x)
			status(t, resp, http.StatusBadRequest, name)
			if !strings.Contains(string(body), "The login did not complete.") {
				t.Fatalf("%s: %s", name, body)
			}
		}
		if got := idpOutcome(t, "provider_error") - before; got < 5 {
			t.Fatalf("provider_error outcomes = %d", got)
		}
		// A good login still works.
		resp, _ = r.run(f.a.NewWeb(), "/login/oidc/google", l)
		status(t, resp, http.StatusSeeOther, "good login after the failures")
	})

	// I35, I36: the start checks.
	t.Run("I35_I36_start_checks", func(t *testing.T) {
		id, web := f.userWithPassword("i35@example.com", demoRole)
		tok := f.adminToken(adminScopes)
		_, itoken := f.inviteUser(tok, "i35b@example.com", demoRole)
		for _, path := range []string{"/login/oidc/google?purpose=link", "/login/oidc/google?purpose=invite&token=" + itoken} {
			for _, site := range []string{"cross-site", "same-site", "none"} {
				w := f.a.NewWeb()
				if strings.Contains(path, "link") {
					w = web
				}
				w.Header.Set("Sec-Fetch-Site", site)
				resp, body := w.Get(t, path)
				status(t, resp, http.StatusBadRequest, path+" "+site)
				if !strings.Contains(string(body), "The login did not complete.") || resp.Header.Get("Location") != "" || len(w.CookiesWithPrefix(pages.IdpCookieName)) != 0 {
					t.Fatalf("%s %s: %s", path, site, body)
				}
				w.Header.Del("Sec-Fetch-Site")
			}
		}
		if f.linkCount(id) != 0 {
			t.Fatal("no link")
		}
		// The purpose login has no rule.
		w := f.a.NewWeb()
		w.Header.Set("Sec-Fetch-Site", "cross-site")
		resp, _ := w.Get(t, "/login/oidc/google")
		status(t, resp, http.StatusFound, "login from another site")
		// I36: return_to and authRequest.
		for _, q := range []string{"return_to=https%3A%2F%2Fevil.example.com%2F", "return_to=%2F%2Fevil.example.com", "authRequest=unknown-request"} {
			w := f.a.NewWeb()
			resp, body := w.Get(t, "/login/oidc/google?"+q)
			status(t, resp, http.StatusBadRequest, q)
			if resp.Header.Get("Location") != "" || !strings.Contains(string(body), "The login did not complete.") || len(w.CookiesWithPrefix(pages.IdpCookieName)) != 0 {
				t.Fatalf("%s: %s", q, body)
			}
		}
		// A provider that is not valid gives 404.
		for _, pr := range []string{"okta", "Google", "microsoft2"} {
			resp, _ := f.a.NewWeb().Get(t, "/login/oidc/"+pr)
			status(t, resp, http.StatusNotFound, pr)
		}
	})

	// I34: the fresh login rules.
	t.Run("I34_fresh_rules", func(t *testing.T) {
		id, web := f.userWithPassword("i34@example.com", demoRole)
		r.link(web, "microsoft", microsoft("o-i34", "i34@example.com"))
		// The login page with prompt=login sends prompt=login to Microsoft. The
		// provider asks the user again, so the token has a new auth_time.
		old := f.clock.Now().Add(-time.Hour)
		l := microsoft("o-i34", "i34@example.com")
		l.AuthTime, l.IssuedAt = old, old
		resp, _ := r.run(f.a.NewWeb(), "/login/oidc/microsoft?prompt=login", l)
		status(t, resp, http.StatusSeeOther, "fresh login with a user step")
		last := p.LastAuthRequest(t)
		if last.Query.Get("prompt") != "login" || !last.UserStep {
			t.Fatalf("last request = %+v", last)
		}
		// A provider that ignores the prompt gives an old token. It is refused.
		before := idpOutcome(t, "not_fresh")
		l.NoUserStep = true
		resp, body := r.run(f.a.NewWeb(), "/login/oidc/microsoft?prompt=login", l)
		status(t, resp, http.StatusBadRequest, "old token with prompt=login")
		if !strings.Contains(string(body), "The login did not complete.") || idpOutcome(t, "not_fresh") != before+1 {
			t.Fatalf("body = %s", body)
		}
		// No prompt: an old token is good.
		resp, _ = r.run(f.a.NewWeb(), "/login/oidc/microsoft", l)
		status(t, resp, http.StatusSeeOther, "old token with no fresh flag")
		// Google gets prompt=select_account for a link.
		g := google("g-i34", "i34-g@example.com")
		r.link(web, "google", g)
		if q := p.LastAuthRequest(t).Query; q.Get("prompt") != "select_account" {
			t.Fatalf("google prompt = %q", q.Get("prompt"))
		}
		// A session older than 5 minutes: the start of a link and the removal go to the login page.
		f.advance(6 * time.Minute)
		resp, _ = web.Get(t, "/login/oidc/google?purpose=link")
		status(t, resp, http.StatusSeeOther, "link with an old session")
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?return_to=") || !strings.Contains(loc, "prompt=login") {
			t.Fatalf("Location = %q", loc)
		}
		resp, _ = web.PostForm(t, "/account/identity-links/microsoft/remove", url.Values{"password": {userPassword}})
		status(t, resp, http.StatusSeeOther, "remove with an old session")
		if !strings.HasPrefix(resp.Header.Get("Location"), "/login?") || f.linkCount(id) != 2 {
			t.Fatalf("Location = %q, links = %d", resp.Header.Get("Location"), f.linkCount(id))
		}
	})

	// I15, I17, I26 and the password page: a user with no password.
	t.Run("I15_no_password", func(t *testing.T) {
		tok := f.adminToken(adminScopes)
		id, itoken := f.inviteUser(tok, "i15@example.com", demoRole)
		web := f.a.NewWeb()
		resp, _ := r.run(web, "/login/oidc/google?purpose=invite&token="+itoken, google("g-i15", "i15@example.com"))
		status(t, resp, http.StatusSeeOther, "invite")
		page := f.page(web, "/account/security")
		if !strings.Contains(page, "Set a password") {
			t.Fatalf("a user with no password sees \"Set a password\": %s", page)
		}
		// The API removal of the only login method.
		tr := r.fedTokens(f.a.NewWeb(), "google", google("g-i15", "i15@example.com"), linkScope)
		resp, m := f.api(tr.AccessToken, http.MethodDelete, "/v1/me/identity-links/google", nil)
		if resp.StatusCode != http.StatusConflict || code(m) != "last_login_method" || f.linkCount(id) != 1 {
			t.Fatalf("remove the only method: %d %v", resp.StatusCode, m)
		}
		// The page removal gives the same answer.
		resp, body := web.PostForm(t, "/account/identity-links/google/remove", url.Values{"password": {userPassword}})
		status(t, resp, http.StatusConflict, "page removal of the only method")
		if !strings.Contains(string(body), "Set a password or an authenticator app first") {
			t.Fatalf("body = %s", body)
		}
		// Set a password on the hosted page, then remove.
		resp, _ = web.Get(t, "/account/password")
		status(t, resp, http.StatusOK, "password page")
		f.a.ledger.add(&f.a.ledger.passwords, userPassword)
		resp, _ = web.PostForm(t, "/account/password", url.Values{"password": {userPassword}, "password2": {"other password long"}})
		status(t, resp, http.StatusBadRequest, "passwords differ")
		resp, _ = web.PostForm(t, "/account/password", url.Values{"password": {"short"}, "password2": {"short"}})
		status(t, resp, http.StatusBadRequest, "short password")
		resp, _ = web.PostForm(t, "/account/password", url.Values{"password": {userPassword}, "password2": {userPassword}})
		status(t, resp, http.StatusSeeOther, "set the password")
		if f.countWhere(`SELECT count(*) FROM users WHERE id = $1 AND password_hash IS NOT NULL`, id) != 1 {
			t.Fatal("the password must be set")
		}
		resp, _ = web.Get(t, "/account/password")
		status(t, resp, http.StatusSeeOther, "password page with a password")
		// The token of the upstream login shows no local factor (P23).
		resp, m = f.api(tr.AccessToken, http.MethodDelete, "/v1/me/identity-links/google", nil)
		if resp.StatusCode != http.StatusUnauthorized || code(m) != "reauthentication_required" || f.linkCount(id) != 1 {
			t.Fatalf("remove with a fed token: %d %v", resp.StatusCode, m)
		}
		pwdTok, _ := f.login("i15@example.com", userPassword, "admin-ui", adminRedirect, linkScope)
		resp, m = f.api(pwdTok.AccessToken, http.MethodDelete, "/v1/me/identity-links/google", nil)
		if resp.StatusCode != http.StatusNoContent || f.linkCount(id) != 0 {
			t.Fatalf("remove after the password: %d %v", resp.StatusCode, m)
		}
		// I28: the audit entry and the notice. No subject and no email.
		if len(auditsOf(t, f.a, "identity:identity_link:remove")) == 0 || len(noticesOf(t, f.a, "identity_link_removed")) == 0 {
			t.Fatal("no audit entry or notice for the removal")
		}
		for _, rec := range recordsOf(t, f.a, "identity.audit") {
			if rec["action"] == "identity:identity_link:remove" {
				changes, _ := rec["changes"].(map[string]any)
				if changes["provider"] != "google" || len(changes) != 1 {
					t.Fatalf("changes = %v", changes)
				}
			}
		}
		// The session of the upstream login ended with the removal.
		resp, _ = web.Get(t, "/account/security")
		status(t, resp, http.StatusSeeOther, "the fed session ended")
		// The link is gone, so the login does not work, and the user logs in with the password.
		resp, _ = r.run(f.a.NewWeb(), "/login/oidc/google", google("g-i15", "i15@example.com"))
		status(t, resp, http.StatusForbidden, "login after the removal")
	})

	// I17: an admin disables and enables a user with no password and a link.
	t.Run("I17_enable", func(t *testing.T) {
		tok := f.adminToken(adminScopes)
		id, itoken := f.inviteUser(tok, "i17@example.com", demoRole)
		resp, _ := r.run(f.a.NewWeb(), "/login/oidc/google?purpose=invite&token="+itoken, google("g-i17", "i17@example.com"))
		status(t, resp, http.StatusSeeOther, "invite")
		for _, c := range []struct {
			disabled bool
			want     string
		}{{true, "disabled"}, {false, "active"}} {
			resp, m := f.api(tok, http.MethodPatch, "/v1/users/"+id, map[string]any{"disabled": c.disabled})
			if resp.StatusCode != http.StatusOK || m["status"] != c.want {
				t.Fatalf("disabled=%v: %d %v", c.disabled, resp.StatusCode, m)
			}
		}
		// A user with no login method gets the status invited.
		id2, itoken2 := f.inviteUser(tok, "i17b@example.com", demoRole)
		resp, _ = r.run(f.a.NewWeb(), "/login/oidc/google?purpose=invite&token="+itoken2, google("g-i17b", "i17b@example.com"))
		status(t, resp, http.StatusSeeOther, "invite 2")
		if _, err := f.a.Pool(t).Exec(ctx, `DELETE FROM identity_links WHERE user_id = $1`, id2); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			disabled bool
			want     string
		}{{true, "disabled"}, {false, "invited"}} {
			resp, m := f.api(tok, http.MethodPatch, "/v1/users/"+id2, map[string]any{"disabled": c.disabled})
			if resp.StatusCode != http.StatusOK || m["status"] != c.want {
				t.Fatalf("user 2, disabled=%v: %d %v", c.disabled, resp.StatusCode, m)
			}
		}
	})

	// I26: the fresh login rule of the own removal.
	t.Run("I26_fresh_removal", func(t *testing.T) {
		id, web := f.userWithPassword("i26@example.com", demoRole)
		r.link(web, "google", google("g-i26", "i26@example.com"))
		tr, _ := f.login("i26@example.com", userPassword, "admin-ui", adminRedirect, linkScope)
		f.advance(6 * time.Minute)
		resp, m := f.api(tr.AccessToken, http.MethodDelete, "/v1/me/identity-links/google", nil)
		if resp.StatusCode != http.StatusUnauthorized || code(m) != "reauthentication_required" ||
			resp.Header.Get("WWW-Authenticate") != `Bearer error="insufficient_user_authentication", error_description="A fresh login is necessary", max_age="300"` {
			t.Fatalf("stale token: %d %v %q", resp.StatusCode, m, resp.Header.Get("WWW-Authenticate"))
		}
		if f.linkCount(id) != 1 {
			t.Fatal("the link stays after a 401")
		}
		tr2, _ := f.login("i26@example.com", userPassword, "admin-ui", adminRedirect, linkScope)
		if resp, _ := f.api(tr2.AccessToken, http.MethodDelete, "/v1/me/identity-links/google", nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("fresh token: %d", resp.StatusCode)
		}
	})

	// I27, I38: the exploit of P2. An attacker with a session of the upstream
	// login loses the session, the refresh token, and the API tokens when the
	// user removes the link.
	for _, route := range []string{"api", "page"} {
		t.Run("I27_I38_exploit_"+route, func(t *testing.T) {
			email := "i27-" + route + "@example.com"
			id, web := f.userWithPassword(email, demoRole)
			login := google("g-i27-"+route, email)
			r.link(web, "google", login)
			// The attacker logs in with the upstream account in a second browser.
			attacker := f.a.NewWeb()
			fed := r.fedTokens(attacker, "google", login, linkScope+" offline_access")
			if fed.RefreshToken == "" {
				t.Fatal("the flow needs a refresh token")
			}
			// The attacker makes an API token. The user has one from the password session.
			resp, m := f.api(fed.AccessToken, http.MethodPost, "/v1/me/api-tokens", map[string]any{"name": "fed token", "scope": "demo:ticket:read"})
			status(t, resp, http.StatusCreated, "API token of the fed session")
			fedValue := testserver.APITokenOf(t, m)
			f.a.ledger.add(&f.a.ledger.apiTokens, fedValue)
			pwd, _ := f.login(email, userPassword, "admin-ui", adminRedirect, linkScope)
			resp, m = f.api(pwd.AccessToken, http.MethodPost, "/v1/me/api-tokens", map[string]any{"name": "pwd token", "scope": "demo:ticket:read"})
			status(t, resp, http.StatusCreated, "API token of the password session")
			f.a.ledger.add(&f.a.ledger.apiTokens, testserver.APITokenOf(t, m))
			if got := f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND name = 'fed token' AND amr = ARRAY['fed']`, id); got != 1 {
				t.Fatalf("the fed token records amr fed: %d", got)
			}
			if got := f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND name = 'pwd token' AND amr = ARRAY['pwd']`, id); got != 1 {
				t.Fatalf("the password token records amr pwd: %d", got)
			}
			// The list does not show the amr.
			resp, m = f.api(pwd.AccessToken, http.MethodGet, "/v1/me/api-tokens", nil)
			status(t, resp, http.StatusOK, "list tokens")
			for _, it := range m["items"].([]any) {
				if _, has := it.(map[string]any)["amr"]; has {
					t.Fatal("the API shows the amr of a token")
				}
			}
			// The user removes the link.
			fresh, _ := f.login(email, userPassword, "admin-ui", adminRedirect, linkScope)
			if route == "api" {
				resp, _ = f.api(fresh.AccessToken, http.MethodDelete, "/v1/me/identity-links/google", nil)
				status(t, resp, http.StatusNoContent, "remove the link")
			} else {
				resp, _ = web.PostForm(t, "/account/identity-links/google/remove", url.Values{"password": {userPassword}})
				status(t, resp, http.StatusSeeOther, "remove the link on the page")
				if resp.Header.Get("Location") != "/account/security" {
					t.Fatalf("a user with no fed session goes to the account page: %q", resp.Header.Get("Location"))
				}
			}
			resp, _ = attacker.Get(t, "/account/security")
			status(t, resp, http.StatusSeeOther, "the session of the attacker")
			resp, rtr := f.a.TokenRequest(t, testserver.RefreshForm("admin-ui", fed.RefreshToken))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("the refresh token of the attacker: %d %v", resp.StatusCode, rtr)
			}
			if f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND name = 'fed token' AND revoked_at IS NOT NULL`, id) != 1 ||
				f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND name = 'pwd token' AND revoked_at IS NULL`, id) != 1 {
				t.Fatal("the fed token ends and the password token stays")
			}
			if resp, _ := f.api(pwd.AccessToken, http.MethodGet, "/v1/me/api-tokens", nil); resp.StatusCode != http.StatusOK {
				t.Fatal("the session with a password stays valid")
			}
			// The own session of a fed user ends too, and the page goes to the login.
			if route == "page" {
				w := f.a.NewWeb()
				r.link(web, "google", login)
				r.fedTokens(w, "google", login, linkScope)
				resp, _ = w.PostForm(t, "/account/identity-links/google/remove", url.Values{"password": {userPassword}})
				// The session of this browser has fed and is not fresh enough only if it is old.
				if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login?removed=1" {
					t.Fatalf("remove in a fed session: %d %q", resp.StatusCode, resp.Header.Get("Location"))
				}
				resp, body := w.Get(t, "/login?removed=1")
				status(t, resp, http.StatusOK, "login after the removal")
				if !strings.Contains(string(body), "The link is removed. Log in again.") {
					t.Fatalf("body = %s", body)
				}
			}
		})
	}

	// I39: the passkey removal revokes the API tokens that a hwk session made.
	t.Run("I29_I39_passkeys", func(t *testing.T) {
		const email = "i39@example.com"
		id := f.newUser(f.adminToken(adminScopes), email, userPassword, demoRole)
		apiScope := passkeyScope + " identity:api_token:manage_own"
		// The token of the password session comes first. A user with a passkey needs
		// the second factor for a password login.
		pwd, _ := f.login(email, userPassword, "admin-ui", adminRedirect, apiScope)
		resp, m := f.api(pwd.AccessToken, http.MethodPost, "/v1/me/api-tokens", map[string]any{"name": "pwd token", "scope": "demo:ticket:read"})
		status(t, resp, http.StatusCreated, "API token of the password session")
		f.a.ledger.add(&f.a.ledger.apiTokens, testserver.APITokenOf(t, m))
		web := f.a.NewWeb()
		f.passwordLogin(web, email, userPassword, "/login/done")
		key := f.newAuthenticator(swa.ES256)
		if resp, m := f.registerPasskey(web, key, "First"); resp.StatusCode != http.StatusOK {
			t.Fatalf("register: %d %v", resp.StatusCode, m)
		}
		u := &passkeyUser{id: id, email: email, password: userPassword, web: web, key: key}
		hwk := f.passkeyToken(u, apiScope)
		resp, m = f.api(hwk, http.MethodPost, "/v1/me/api-tokens", map[string]any{"name": "hwk token", "scope": "demo:ticket:read"})
		status(t, resp, http.StatusCreated, "API token of the hwk session")
		f.a.ledger.add(&f.a.ledger.apiTokens, testserver.APITokenOf(t, m))
		if f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND name = 'hwk token' AND 'hwk' = ANY(amr)`, u.id) != 1 ||
			f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND name = 'pwd token' AND NOT 'hwk' = ANY(amr)`, u.id) != 1 {
			t.Fatal("the tokens record the amr of their sessions")
		}
		resp, _ = u.web.PostForm(t, "/account/passkeys/"+f.passkeyIDs(u.id)[0]+"/remove", nil)
		status(t, resp, http.StatusSeeOther, "page removal of the passkey")
		if f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND name = 'hwk token' AND revoked_at IS NOT NULL`, u.id) != 1 ||
			f.countWhere(`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND name = 'pwd token' AND revoked_at IS NULL`, u.id) != 1 {
			t.Fatal("the hwk token ends and the password token stays")
		}
		// I29: a user with no password and no link cannot remove the last passkey.
		tok := f.adminToken(adminScopes)
		id2, itoken := f.inviteUser(tok, "i29@example.com", demoRole)
		web2 := f.a.NewWeb()
		resp, _ = r.run(web2, "/login/oidc/google?purpose=invite&token="+itoken, google("g-i29", "i29@example.com"))
		status(t, resp, http.StatusSeeOther, "invite")
		key2 := f.newAuthenticator(swa.ES256)
		if resp, m := f.registerPasskey(web2, key2, "Only"); resp.StatusCode != http.StatusOK {
			t.Fatalf("register: %d %v", resp.StatusCode, m)
		}
		// The link is a login method, so the passkey can go. Without the link it cannot.
		if _, err := f.a.Pool(t).Exec(ctx, `DELETE FROM identity_links WHERE user_id = $1`, id2); err != nil {
			t.Fatal(err)
		}
		access := f.passkeyToken(&passkeyUser{id: id2, email: "i29@example.com", web: web2, key: key2}, passkeyScope)
		resp, m = f.api(access, http.MethodDelete, "/v1/me/passkeys/"+f.passkeyIDs(id2)[0], nil)
		if resp.StatusCode != http.StatusConflict || code(m) != "last_login_method" || f.passkeyRows(id2) != 1 {
			t.Fatalf("remove the last passkey: %d %v", resp.StatusCode, m)
		}
	})

	// I21, I22: no secret in a log record or a span, and only the provider host.
	t.Run("I21_I22_no_secrets", func(t *testing.T) {
		for _, h := range p.Hosts() {
			if !slices.Contains(oidcprovider.ProviderHosts(), h) {
				t.Fatalf("a call to the host %q", h)
			}
		}
		if len(p.Hosts()) == 0 {
			t.Fatal("the provider got no call")
		}
		h.ledger.mu.Lock()
		defer h.ledger.mu.Unlock()
		if len(h.ledger.flow) < 50 {
			t.Fatalf("the ledger has %d values", len(h.ledger.flow))
		}
		spans := spansText()
		text := f.a.logs.Text()
		for _, v := range append(append([]string{}, h.ledger.flow...), h.ledger.apiTokens...) {
			if v == "" {
				continue
			}
			if strings.Contains(text, v) {
				i := strings.Index(text, v)
				t.Fatalf("a log record holds the secret %q: %s", v[:min(len(v), 8)], text[max(0, i-200):min(len(text), i+100)])
			}
			if strings.Contains(spans, v) {
				t.Fatalf("a span holds the secret %q", v[:min(len(v), 8)])
			}
		}
		// The subject and the email of the upstream accounts are not in the log.
		for _, v := range []string{"g-i4", "g-i5", "i4-up@example.com", "i5-new@example.com", "g-unlinked", oidcprovider.TenantA + ":o-i13"} {
			if strings.Contains(text, v) {
				t.Fatalf("a log record holds %q", v)
			}
			if strings.Contains(spans, v) {
				t.Fatalf("a span holds %q", v)
			}
		}
	})
}
