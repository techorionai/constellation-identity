//go:build integration

package services_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-platform-go/auth"
	"github.com/techorionai/constellation-platform-go/resources/test/containers"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
	"github.com/techorionai/constellation-identity/internal/services"
	"github.com/techorionai/constellation-identity/resources/test/oidcprovider"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
	swa "github.com/techorionai/constellation-identity/resources/test/webauthn"
)

// entriesOf waits until the stream has at least n entries that match and that
// the relay has published all rows of the outbox. It returns the entries.
func entriesOf(t *testing.T, a *app, n int, match func(testserver.AuditRecord) bool) []testserver.AuditRecord {
	t.Helper()
	a.WaitAuditRelayed(t)
	return a.audit.Wait(t, n, match)
}

// byAction matches the entries with the action and an optional target ID.
func byAction(action, targetID string) func(testserver.AuditRecord) bool {
	return func(r testserver.AuditRecord) bool {
		return r.Data.Action == action && (targetID == "" || (r.Data.Target != nil && r.Data.Target.ID == targetID))
	}
}

// jtiOf returns the jti claim of a token.
func jtiOf(t *testing.T, tok string) string {
	t.Helper()
	_, c := testserver.JWTClaims(t, tok)
	jti, _ := c["jti"].(string)
	if jti == "" {
		t.Fatal("the token has no jti")
	}
	return jti
}

// withOwnValkey starts a fixture on a new Valkey container and gives it an
// audit reader for that container.
func withOwnValkey(t *testing.T, h *harness, opts ...testserver.Option) (*fixture, *containers.ValkeyInstance) {
	t.Helper()
	g, vk := rlFixture(t, h, opts...)
	g.a.audit = (&testserver.Env{PG: h.env.PG, VK: vk}).NewAuditReader(t)
	return g, vk
}

// The tests of the audit entries of the signing keys, the tokens, the logins,
// and the operator commands. The tests use PostgreSQL and Valkey. A test reader
// reads audit.stream:identity. Each test waits a maximum of 10 seconds for an
// entry, because the relay of the running server publishes the outbox rows.
func TestIssue26Integration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}
	p := oidcprovider.Start(t)
	f := newFixture(t, h, mfaOptions(testserver.WithIdp(testserver.IdpSettings{Provider: p, Google: true, Microsoft: true}))...)
	r := newIdpRig(f, p)
	r.track("google-client-secret", "microsoft-client-secret", "UPSTREAM-ACCESS-", "UPSTREAM-REFRESH-")
	demo := f.serviceClient
	const demoRole = "demo:agent"

	// I1: the startup on a new database. The first key is created active, so the
	// pass writes a create entry with the state active and no activate entry.
	t.Run("I1_startup", func(t *testing.T) {
		kid, _ := jwksKeys(t, f.a.Server)[0]["kid"].(string)
		got := entriesOf(t, f.a, 1, byAction("identity:signing_key:create", kid))
		e := got[0]
		if e.Actor != "identity" || e.ActorType != "service" || e.Data.Result != "success" || e.Data.Target.Type != "signing_key" {
			t.Fatalf("entry = %s", e.Raw)
		}
		if _, has := e.Data.Details["origin"]; has || e.Data.Details["state"] != "active" || e.Data.Details["kid"] != kid || e.Data.Details["algorithm"] == "" {
			t.Fatalf("details = %v", e.Data.Details)
		}
	})

	// I2: a rotation with short test periods writes the entries of create,
	// activate, retire, and delete. No entry has an origin.
	t.Run("I2_rotation", func(t *testing.T) {
		g := h.start(t,
			testserver.WithKeyPolicy(domain.KeyPolicy{RotationPeriod: 2 * time.Second, PublishDelay: time.Second, RetireAfter: time.Second}),
			testserver.WithKeyIntervals(200*time.Millisecond, 200*time.Millisecond))
		first, _ := jwksKeys(t, g.Server)[0]["kid"].(string)
		deadline := time.Now().Add(40 * time.Second)
		var kids = map[string]bool{}
		for {
			g.WaitAuditRelayed(t)
			var del, retire, activate bool
			for _, e := range g.audit.All(t) {
				switch {
				case e.Data.Action == "identity:signing_key:delete" && e.Data.Target.ID == first:
					del = true
				case e.Data.Action == "identity:signing_key:retire" && e.Data.Target.ID == first:
					retire = true
				case e.Data.Action == "identity:signing_key:activate" && e.Data.Details["previousKid"] == first:
					activate = true
					kids[e.Data.Target.ID] = true
				}
			}
			if del && retire && activate {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("entries: delete %v, retire %v, activate %v", del, retire, activate)
			}
			time.Sleep(200 * time.Millisecond)
		}
		for _, e := range g.audit.All(t) {
			if !strings.HasPrefix(e.Data.Action, "identity:signing_key:") || e.Data.Action == "identity:signing_key:force_rotate" {
				continue
			}
			if e.Actor != "identity" || e.ActorType != "service" {
				t.Fatalf("entry = %s", e.Raw)
			}
			if _, has := e.Data.Details["origin"]; has {
				t.Fatalf("an automatic key action has an origin: %s", e.Raw)
			}
			if e.Data.Action == "identity:signing_key:delete" && e.Data.Target.ID == first && e.Data.Details["forced"] != false {
				t.Fatalf("delete entry = %s", e.Raw)
			}
		}
		pending := g.audit.Find(t, "identity:signing_key:create")
		var sawPending bool
		for _, e := range pending {
			if e.Data.Details["state"] == "pending" {
				sawPending = true
			}
		}
		if !sawPending {
			t.Fatal("no create entry with the state pending")
		}
	})

	// I3: rotate-signing-keys --force. The command writes the outbox rows. The
	// relay of the running server publishes them.
	t.Run("I3_force_rotate", func(t *testing.T) {
		g := h.start(t)
		old, _ := jwksKeys(t, g.Server)[0]["kid"].(string)
		if err := services.ForceRotateSigningKeys(ctx, g.Config, discardLog()); err != nil {
			t.Fatal(err)
		}
		var fresh string
		if err := g.Pool(t).QueryRow(ctx, `SELECT kid FROM signing_keys WHERE state = 'active'`).Scan(&fresh); err != nil || fresh == old {
			t.Fatalf("new kid = %q, old = %q, err = %v", fresh, old, err)
		}
		rot := entriesOf(t, g, 1, byAction("identity:signing_key:force_rotate", fresh))[0]
		if rot.Actor != "identity" || rot.ActorType != "service" || rot.Data.Details["origin"] != "cli" ||
			rot.Data.Details["newKid"] != fresh || rot.Data.Details["deletedKeys"] != float64(1) {
			t.Fatalf("force_rotate = %s", rot.Raw)
		}
		del := entriesOf(t, g, 1, byAction("identity:signing_key:delete", old))[0]
		if del.Data.Details["forced"] != true || del.Data.Details["origin"] != "cli" || del.Actor != "identity" {
			t.Fatalf("delete = %s", del.Raw)
		}
		create := entriesOf(t, g, 1, func(e testserver.AuditRecord) bool {
			return e.Data.Action == "identity:signing_key:create" && e.Data.Target.ID == fresh
		})[0]
		if create.Data.Details["origin"] != "cli" {
			t.Fatalf("create = %s", create.Raw)
		}
	})

	// I4: the client credentials grant.
	t.Run("I4_client_credentials", func(t *testing.T) {
		tok := token(t, f.a.Server, demo, "identity", "identity:manifest:publish")
		jti := jtiOf(t, tok)
		e := entriesOf(t, f.a, 1, func(r testserver.AuditRecord) bool {
			return r.Data.Action == "identity:token:issue" && r.Data.Details["jti"] == jti
		})[0]
		if e.Actor != "demo" || e.ActorType != "service" || e.Data.Result != "success" || e.Data.Target.Type != "client" || e.Data.Target.ID != "demo" {
			t.Fatalf("entry = %s", e.Raw)
		}
		d := e.Data.Details
		if d["grant"] != "client_credentials" || d["clientId"] != "demo" || d["audience"] != "identity" || d["expiresAt"] == nil ||
			fmt.Sprint(d["scopes"]) != "[identity:manifest:publish]" {
			t.Fatalf("details = %v", d)
		}
		if strings.Contains(e.Raw, tok) {
			t.Fatal("the entry has the token")
		}
	})

	// I5: the authorization code flow and one refresh.
	var refreshOne string
	var userI5 string
	t.Run("I5_code_and_refresh", func(t *testing.T) {
		userI5 = f.newUser(f.adminToken(adminScopes), "i26-5@example.com", userPassword, demoRole)
		tr, _ := f.login("i26-5@example.com", userPassword, "demo-ui", demoRedirect, demoScope)
		code := entriesOf(t, f.a, 1, func(r testserver.AuditRecord) bool {
			return r.Data.Action == "identity:token:issue" && r.Data.Details["jti"] == jtiOf(t, tr.AccessToken)
		})[0]
		if code.Actor != "demo-ui" || code.ActorType != "service" || code.Data.Target.Type != "user" || code.Data.Target.ID != userI5 ||
			code.Data.Details["grant"] != "authorization_code" || code.Data.Details["audience"] != "demo" {
			t.Fatalf("code entry = %s", code.Raw)
		}
		refreshOne = tr.RefreshToken
		resp, tr2 := f.a.TokenRequest(t, testserver.RefreshForm("demo-ui", tr.RefreshToken))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("refresh: %d %s", resp.StatusCode, tr2.Error)
		}
		f.a.ledger.add(&f.a.ledger.flow, tr2.RefreshToken)
		ref := entriesOf(t, f.a, 1, func(r testserver.AuditRecord) bool {
			return r.Data.Action == "identity:token:issue" && r.Data.Details["jti"] == jtiOf(t, tr2.AccessToken)
		})[0]
		if ref.Actor != "demo-ui" || ref.Data.Target.ID != userI5 || ref.Data.Details["grant"] != "refresh_token" || ref.Data.Result != "success" {
			t.Fatalf("refresh entry = %s", ref.Raw)
		}
	})

	// I6: the token exchange of an agent for a user, and an exchange with no agent.
	t.Run("I6_token_exchange", func(t *testing.T) {
		x := newExchangeFixture(t, h, f)
		x.grantExchange("demo")
		userID, subject := x.subjectFor("i26-6", "extra:editor")
		agentID := x.newAgent("I26 agent", "demo", "extra:viewer")
		tok, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, AgentID: agentID, Audience: "extra", Scopes: []string{extraRead}})
		if err != nil {
			t.Fatal(err)
		}
		e := entriesOf(t, f.a, 1, func(r testserver.AuditRecord) bool {
			return r.Data.Action == "identity:token:issue" && r.Data.Details["jti"] == jtiOf(t, tok)
		})[0]
		if e.Actor != agentID || e.ActorType != "agent" || e.Act != "" || e.Data.Target.Type != "user" || e.Data.Target.ID != userID ||
			e.Data.Details["grant"] != "token_exchange" || e.Data.Details["subjectType"] != "user" || e.Data.Details["clientId"] != "demo" {
			t.Fatalf("entry = %s", e.Raw)
		}
		tok2, err := x.exchange(demo, auth.ExchangeRequest{SubjectToken: subject, Audience: "extra", Scopes: []string{extraRead}})
		if err != nil {
			t.Fatal(err)
		}
		e2 := entriesOf(t, f.a, 1, func(r testserver.AuditRecord) bool {
			return r.Data.Action == "identity:token:issue" && r.Data.Details["jti"] == jtiOf(t, tok2)
		})[0]
		if e2.Actor != "demo" || e2.ActorType != "service" || e2.Data.Target.ID != userID {
			t.Fatalf("no agent: entry = %s", e2.Raw)
		}
	})

	// I7: a client credentials request with a wrong key, and a refresh token reuse.
	t.Run("I7_denied", func(t *testing.T) {
		wrong := testserver.NewServiceClient(t, "demo", "demo")
		resp, body := f.a.PostToken(t, testserver.TokenForm(f.a.Assertion(t, wrong, nil), "identity", "identity:manifest:publish"))
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "invalid_client") {
			t.Fatalf("wrong key: %d %s", resp.StatusCode, body)
		}
		bad := entriesOf(t, f.a, 1, func(r testserver.AuditRecord) bool {
			return r.Data.Action == "identity:token:issue" && r.Data.Result == "denied" && r.Data.Details["reason"] == "invalid_client"
		})[0]
		if bad.Actor != "identity" || bad.ActorType != "service" || bad.Data.Details["clientId"] != "demo" || bad.Data.Details["grant"] != "client_credentials" {
			t.Fatalf("invalid_client entry = %s", bad.Raw)
		}
		// The first refresh token of I5 was used. A second use is a reuse.
		resp, tr := f.a.TokenRequest(t, testserver.RefreshForm("demo-ui", refreshOne))
		if resp.StatusCode != http.StatusBadRequest || tr.Error != "invalid_grant" {
			t.Fatalf("reuse: %d %s", resp.StatusCode, tr.Error)
		}
		reuse := entriesOf(t, f.a, 1, func(r testserver.AuditRecord) bool {
			return r.Data.Action == "identity:token:issue" && r.Data.Details["reason"] == "refresh_token_reuse"
		})[0]
		if reuse.Data.Result != "denied" || reuse.Actor != "identity" || reuse.Data.Details["grant"] != "refresh_token" || reuse.Data.Details["clientId"] != "demo-ui" {
			t.Fatalf("reuse entry = %s", reuse.Raw)
		}
	})

	// I8 and I16: a password login with TOTP, a failed password login, a wrong
	// TOTP code, and a login with a recovery code.
	t.Run("I8_I16_password_and_totp", func(t *testing.T) {
		u := f.newTOTPUser("i26-8@example.com", demoRole)
		f.mfaToken(u, "admin-ui", adminRedirect, mfaScope, nil)
		ok := entriesOf(t, f.a, 1, func(e testserver.AuditRecord) bool {
			return e.Data.Action == "identity:session:login" && e.Data.Result == "success" && e.Actor == u.id && e.Data.Details["mfa"] == "totp"
		})[0]
		if ok.ActorType != "user" || ok.Data.Details["method"] != "password" || ok.Data.Target.ID != u.id {
			t.Fatalf("success entry = %s", ok.Raw)
		}
		// A wrong password for a known and for an unknown email.
		for _, email := range []string{u.email, "nobody-i26@example.com"} {
			resp, _ := f.a.NewWeb().PostForm(t, "/login", url.Values{"email": {email}, "password": {"wrong password 123456"}})
			if resp.StatusCode == http.StatusSeeOther {
				t.Fatalf("a wrong password gave a redirect for %s", email)
			}
		}
		f.a.WaitAuditRelayed(t)
		var known, unknown bool
		for _, e := range f.a.audit.Find(t, "identity:session:login") {
			if e.Data.Result != "denied" || e.Data.Details["method"] != "password" {
				continue
			}
			if e.Actor != "identity" || e.ActorType != "service" {
				t.Fatalf("denied entry = %s", e.Raw)
			}
			switch {
			case e.Data.Target != nil && e.Data.Target.ID == u.id:
				known = true
			case e.Data.Target == nil:
				unknown = true
			}
		}
		if !known || !unknown {
			t.Fatalf("denied entries: known user %v, unknown email %v", known, unknown)
		}
		// I16: a wrong TOTP code, then a recovery code.
		f.advance(31 * time.Second)
		pk := testserver.NewPKCE(t)
		f.startMFALogin(u.web, testserver.AuthorizeQuery("admin-ui", adminRedirect, mfaScope, pk, map[string]string{"prompt": "login"}), u.email, u.password)
		resp, _ := u.web.PostForm(t, "/login/mfa", url.Values{"code": {"000000"}})
		if resp.StatusCode == http.StatusSeeOther {
			t.Fatal("a wrong code gave a redirect")
		}
		bad := entriesOf(t, f.a, 1, func(e testserver.AuditRecord) bool {
			return e.Data.Action == "identity:session:login" && e.Data.Result == "denied" && e.Data.Details["reason"] == "mfa_failed"
		})[0]
		if bad.Actor != "identity" || bad.Data.Details["mfa"] != "totp" || bad.Data.Details["method"] != "password" || bad.Data.Target.ID != u.id {
			t.Fatalf("mfa_failed entry = %s", bad.Raw)
		}
		f.finishMFALogin(u.web, u.codes[0], true)
		rec := entriesOf(t, f.a, 1, func(e testserver.AuditRecord) bool {
			return e.Data.Action == "identity:session:login" && e.Data.Result == "success" && e.Data.Details["mfa"] == "recovery_code"
		})[0]
		if rec.Actor != u.id || rec.Data.Details["method"] != "password" {
			t.Fatalf("recovery entry = %s", rec.Raw)
		}
	})

	// I9: unlock-login for a locked user.
	t.Run("I9_unlock_login", func(t *testing.T) {
		id, _ := f.userWithPassword("i26-9@example.com", demoRole)
		for range 3 {
			f.a.NewWeb().PostForm(t, "/login", url.Values{"email": {"i26-9@example.com"}, "password": {"wrong password 123456"}})
		}
		unlocked, err := services.UnlockLogin(ctx, f.a.Config, "I26-9@Example.com", discardLog())
		if err != nil || !unlocked {
			t.Fatalf("unlock = %v, %v", unlocked, err)
		}
		e := entriesOf(t, f.a, 1, byAction("identity:login:unlock", id))[0]
		if e.Actor != "identity" || e.ActorType != "service" || e.Data.Target.Type != "user" || e.Data.Details["origin"] != "cli" ||
			e.Data.Details["knownUser"] != true || e.Data.Details["wasLocked"] != true || strings.Contains(e.Raw, "example.com") {
			t.Fatalf("entry = %s", e.Raw)
		}
		// An email that no user has: no target and knownUser false.
		if _, err := services.UnlockLogin(ctx, f.a.Config, "nobody-i26-9@example.com", discardLog()); err != nil {
			t.Fatal(err)
		}
		u := entriesOf(t, f.a, 1, func(r testserver.AuditRecord) bool {
			return r.Data.Action == "identity:login:unlock" && r.Data.Target == nil
		})[0]
		if u.Data.Details["knownUser"] != false || strings.Contains(u.Raw, "nobody") {
			t.Fatalf("unknown entry = %s", u.Raw)
		}
	})

	// I10: unlock-login with Valkey stopped. The command fails and writes no entry.
	t.Run("I10_unlock_valkey_down", func(t *testing.T) {
		vk, g := h.startOwnValkey(t)
		const q = `SELECT count(*) FROM platform_audit_outbox WHERE payload->'data'->>'action' = 'identity:login:unlock'`
		before := count(t, g.Server, q)
		if err := vk.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := services.UnlockLogin(ctx, g.Config, "admin@example.com", discardLog()); err == nil {
			t.Fatal("unlock with Valkey stopped must fail")
		}
		after := count(t, g.Server, q)
		if before != after {
			t.Fatalf("outbox rows of unlock: %d before, %d after", before, after)
		}
	})

	// I11: setup-link and set-idp-secret. The entries have no link, token, or secret.
	t.Run("I11_setup_link_and_idp_secret", func(t *testing.T) {
		if err := services.SetIdpSecret(ctx, f.a.Config, "google", "i26-secret-value", discardLog()); err != nil {
			t.Fatal(err)
		}
		s := entriesOf(t, f.a, 1, byAction("identity:idp:secret_set", "google"))[0]
		if s.Actor != "identity" || s.Data.Details["origin"] != "cli" || s.Data.Details["provider"] != "google" || strings.Contains(s.Raw, "i26-secret-value") {
			t.Fatalf("secret_set = %s", s.Raw)
		}
		// A new install has no admin, so setup-link works there.
		fresh := h.env.NewDB(t)
		cfg := h.env.Config(t, testserver.WithDB(fresh), testserver.WithMasterKey(h.masterKey, "test"))
		link, err := services.SetupLink(ctx, cfg, discardLog())
		if err != nil {
			t.Fatal(err)
		}
		srv := h.start(t, testserver.WithDB(fresh))
		e := entriesOf(t, srv, 1, byAction("identity:setup:link_create", ""))[0]
		if e.Actor != "identity" || e.Data.Details["origin"] != "cli" || strings.Contains(e.Raw, testserver.TokenOf(t, link)) || strings.Contains(e.Raw, "/setup") {
			t.Fatalf("link_create = %s", e.Raw)
		}
	})

	// I14: a passkey login.
	t.Run("I14_passkey", func(t *testing.T) {
		u := f.newPasskeyUser("i26-14@example.com", swa.ES256, demoRole)
		f.passkeyCodeFlow(f.a.NewWeb(), u.key, "admin-ui", adminRedirect, mfaScope, nil)
		e := entriesOf(t, f.a, 1, func(r testserver.AuditRecord) bool {
			return r.Data.Action == "identity:session:login" && r.Data.Result == "success" && r.Data.Details["method"] == "passkey" && r.Actor == u.id
		})[0]
		if e.ActorType != "user" || e.Data.Target.ID != u.id {
			t.Fatalf("entry = %s", e.Raw)
		}
	})

	// I15: an upstream login.
	t.Run("I15_upstream", func(t *testing.T) {
		id, web := f.userWithPassword("i26-15@example.com", demoRole)
		r.link(web, "google", google("g-i26-15", "i26-15-up@example.com"))
		r.fedTokens(f.a.NewWeb(), "google", google("g-i26-15", "i26-15-up@example.com"), linkScope)
		e := entriesOf(t, f.a, 1, func(x testserver.AuditRecord) bool {
			return x.Data.Action == "identity:session:login" && x.Data.Result == "success" && x.Data.Details["method"] == "upstream" && x.Actor == id
		})[0]
		if strings.Contains(e.Raw, "i26-15") && strings.Contains(e.Raw, "@") {
			t.Fatalf("the entry has an email: %s", e.Raw)
		}
	})

	// I13: more bad client requests than the token IP limit. The requests over the
	// limit get 429 and write no entry. A request with invalid_request writes none.
	t.Run("I13_token_ip_limit", func(t *testing.T) {
		g, _ := withOwnValkey(t, h, testserver.WithRateLimits(map[string]ratelimit.Rule{ratelimit.BucketTokenIP: {Limit: 5, Window: time.Hour}}))
		invalid := testserver.TokenForm(g.a.Assertion(t, g.serviceClient, nil), "identity", "identity:manifest:publish")
		invalid.Del("grant_type")
		if resp, _ := g.a.PostToken(t, invalid); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid_request: status = %d", resp.StatusCode)
		}
		wrong := testserver.NewServiceClient(t, "demo", "demo")
		var limited int
		for range 7 {
			resp, _ := g.a.PostToken(t, testserver.TokenForm(g.a.Assertion(t, wrong, nil), "identity", "identity:manifest:publish"))
			if resp.StatusCode == http.StatusTooManyRequests {
				limited++
			}
		}
		g.a.WaitAuditRelayed(t)
		var denied int
		for _, e := range g.a.audit.Find(t, "identity:token:issue") {
			if e.Data.Result == "denied" {
				denied++
			}
		}
		// The limit is 5. The invalid_request used one place. Four bad requests fit.
		if limited != 3 || denied != 4 {
			t.Fatalf("429 = %d, denied entries = %d, want 3 and 4", limited, denied)
		}
	})

	// I17: more failed logins than the login limit.
	t.Run("I17_login_limit", func(t *testing.T) {
		g, _ := withOwnValkey(t, h, testserver.WithConfigure(func(c *config.Config) { c.Login.MaxFailuresPerEmail = 3 }))
		id := g.newUser(g.adminToken(adminScopes), "i26-17@example.com", userPassword, demoRole)
		var limited int
		for range 5 {
			resp, _ := g.a.NewWeb().PostForm(t, "/login", url.Values{"email": {"i26-17@example.com"}, "password": {"wrong password 123456"}})
			if resp.StatusCode == http.StatusTooManyRequests {
				limited++
			}
		}
		g.a.WaitAuditRelayed(t)
		var denied int
		for _, e := range g.a.audit.Find(t, "identity:session:login") {
			if e.Data.Result == "denied" && e.Data.Target != nil && e.Data.Target.ID == id {
				denied++
			}
		}
		if limited != 2 || denied != 3 {
			t.Fatalf("429 = %d, denied entries = %d, want 2 and 3", limited, denied)
		}
	})

	// I18: a failure of the audit insert gives no token, and no login session.
	t.Run("I18_audit_failure", func(t *testing.T) {
		g := newFixtureOn(t, h.start)
		pool := g.a.Pool(t)
		for _, q := range []string{
			`CREATE FUNCTION i26_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit down'; END $$`,
			`CREATE TRIGGER i26_fail BEFORE INSERT ON platform_audit_outbox FOR EACH ROW EXECUTE FUNCTION i26_fail_audit()`,
		} {
			if _, err := pool.Exec(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
		resp, body := g.a.PostToken(t, testserver.TokenForm(g.a.Assertion(t, g.serviceClient, nil), "identity", "identity:manifest:publish"))
		if resp.StatusCode != http.StatusServiceUnavailable || strings.Contains(string(body), "access_token") {
			t.Fatalf("token request: %d %s, want 503 and no token", resp.StatusCode, body)
		}
		sessions := g.countWhere(`SELECT count(*) FROM sessions`)
		resp, _ = g.a.NewWeb().PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {adminPassword}})
		if resp.StatusCode == http.StatusSeeOther || g.countWhere(`SELECT count(*) FROM sessions`) != sessions {
			t.Fatalf("login: status = %d, want no session", resp.StatusCode)
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER i26_fail ON platform_audit_outbox`); err != nil {
			t.Fatal(err)
		}
		if resp, body = g.a.PostToken(t, testserver.TokenForm(g.a.Assertion(t, g.serviceClient, nil), "identity", "identity:manifest:publish")); resp.StatusCode != http.StatusOK {
			t.Fatalf("after the repair: %d %s", resp.StatusCode, body)
		}
	})

	// I12: no entry of this issue has a token text, a secret, a private key, or an
	// email address. The log has no audit record.
	t.Run("I12_no_secrets", func(t *testing.T) {
		f.a.WaitAuditRelayed(t)
		mine := map[string]bool{
			"identity:token:issue": true, "identity:session:login": true, "identity:login:unlock": true,
			"identity:setup:link_create": true, "identity:idp:secret_set": true,
		}
		l := f.a.ledger
		l.mu.Lock()
		secrets := append(append(append([]string{}, l.flow...), l.exchange...), l.passwords...)
		l.mu.Unlock()
		var n int
		for _, e := range f.a.audit.All(t) {
			if !mine[e.Data.Action] && !strings.HasPrefix(e.Data.Action, "identity:signing_key:") {
				continue
			}
			n++
			if strings.Contains(e.Raw, "PRIVATE KEY") || strings.Contains(e.Raw, "@example.com") {
				t.Fatalf("entry has a private key or an email: %s", e.Raw)
			}
			for _, s := range secrets {
				if len(s) >= 8 && strings.Contains(e.Raw, s) {
					t.Fatalf("entry has a secret: %s", e.Raw)
				}
			}
		}
		if n == 0 {
			t.Fatal("no entry was checked")
		}
		for _, rec := range f.a.logs.Records(t) {
			if rec["msg"] == "identity.audit" {
				t.Fatalf("log record = %v", rec)
			}
		}
	})
}
