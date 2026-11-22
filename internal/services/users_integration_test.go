//go:build integration

package services_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/techorionai/constellation-platform-go/resources/test/containers"
	"github.com/techorionai/constellation-platform-go/retention"
	transactionpg "github.com/techorionai/constellation-platform-go/transaction/postgres"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/techorionai/constellation-identity/internal/adapters/argon2"
	"github.com/techorionai/constellation-identity/internal/adapters/postgres"
	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/internal/services"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

const (
	adminPassword = "admin password 7731 long"
	userPassword  = "user password 4482 long"
)

var (
	obsOnce      sync.Once
	spanExporter *tracetest.InMemoryExporter
	metricReader *sdkmetric.ManualReader
)

// observability sets the global trace and metric providers one time, so that a
// test can read the spans and the metrics of the services.
func observability() {
	obsOnce.Do(func() {
		spanExporter = tracetest.NewInMemoryExporter()
		otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSyncer(spanExporter)))
		metricReader = sdkmetric.NewManualReader()
		otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(metricReader)))
	})
}

// loginCount returns the value of the counter identity.logins for an outcome.
func loginCount(t *testing.T, outcome string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := metricReader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if m.Name != "identity.logins" || !ok {
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

// passwordRuns returns the number of argon2 computations (hash and verify)
// since the start of the test process.
func passwordRuns(t *testing.T) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := metricReader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if m.Name != "identity.password.runs" || !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
		}
	}
	return total
}

// secretLedger collects the secrets of all tests, so that the last test can
// check that no log record and no span holds one.
type secretLedger struct {
	mu        sync.Mutex
	logs      []*testserver.LogCapture
	passwords []string
	sessions  []string
	invites   []string
	setups    []string
	printed   []string
	// flow has the values of the code flow: codes, verifiers, refresh tokens,
	// ID tokens, and auth request IDs.
	flow []string
}

func (l *secretLedger) add(dst *[]string, v string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	*dst = append(*dst, v)
}

// harness starts servers with a log capture and remembers the secrets.
type harness struct {
	env    *testserver.Env
	ledger *secretLedger
	// masterKey is the master key of all servers, so a restart on the same
	// database can decrypt the signing key.
	masterKey string
}

type app struct {
	*testserver.Server
	logs   *testserver.LogCapture
	ledger *secretLedger
}

func (h *harness) start(t *testing.T, opts ...testserver.Option) *app {
	t.Helper()
	logs := testserver.NewLogCapture()
	h.ledger.mu.Lock()
	h.ledger.logs = append(h.ledger.logs, logs)
	h.ledger.mu.Unlock()
	opts = append([]testserver.Option{testserver.WithLogger(logs.Logger()), testserver.WithMasterKey(h.masterKey, "test")}, opts...)
	s := h.env.Start(t, opts...)
	return &app{Server: s, logs: logs, ledger: h.ledger}
}

// startOwnValkey starts a server with a new Valkey container, so that the login
// counters of other tests do not count. The tests share the client IP of the
// local host.
func (h *harness) startOwnValkey(t *testing.T) (*containers.ValkeyInstance, *app) {
	t.Helper()
	vk := containers.Valkey(t, containers.WithValkeyImage(testserver.ValkeyImage))
	env := &testserver.Env{PG: h.env.PG, VK: vk}
	logs := testserver.NewLogCapture()
	h.ledger.mu.Lock()
	h.ledger.logs = append(h.ledger.logs, logs)
	h.ledger.mu.Unlock()
	s := env.Start(t, testserver.WithLogger(logs.Logger()), testserver.WithMasterKey(h.masterKey, "test"))
	return vk, &app{Server: s, logs: logs, ledger: h.ledger}
}

// setupLink gets a setup link as the operator does, with the same code as the
// subcommand setup-link. The link is not in the log. The test remembers the
// token, so that I12 checks that no log record and no span holds it.
func (a *app) setupLink(t *testing.T) string {
	t.Helper()
	link, err := services.SetupLink(ctx, a.Config, a.logs.Logger())
	if err != nil {
		t.Fatalf("setup link: %v", err)
	}
	a.ledger.add(&a.ledger.setups, testserver.TokenOf(t, link))
	return link
}

func (a *app) trackSession(web *testserver.Web) {
	if v := web.Cookie(pages.CookieName); v != "" {
		a.ledger.add(&a.ledger.sessions, v)
	}
}

// completeSetup posts the setup form and returns the browser.
func (a *app) completeSetup(t *testing.T, link, email, name, password string) (*testserver.Web, testserver.Response) {
	t.Helper()
	web := a.NewWeb()
	a.ledger.add(&a.ledger.passwords, password)
	resp, _ := web.PostForm(t, "/setup", url.Values{
		"token": {testserver.TokenOf(t, link)}, "email": {email}, "name": {name},
		"password": {password}, "password2": {password},
	})
	a.trackSession(web)
	return web, resp
}

// userCommands makes the use cases of the invites on the database of the
// server. The admin API of a later issue will call the same use cases.
type userCommands struct {
	create *commands.CreateUserCommand
	invite *commands.CreateInviteCommand
	users  *postgres.Users
}

func (a *app) commands(t *testing.T) userCommands {
	t.Helper()
	pool := a.Pool(t)
	hasher, err := argon2.New(argon2.Config{MaxConcurrent: 1, QueueTimeout: time.Second, MemoryKiB: 1024, Time: 1})
	if err != nil {
		t.Fatal(err)
	}
	d := commands.InviteDeps{
		Issuer: a.Config.Issuer, TTL: a.Config.Invite.TTL,
		Tokens: postgres.NewOneTimeTokens(pool), Users: postgres.NewUsers(pool), Session: postgres.NewSessions(pool),
		Hasher: hasher, Tx: transactionpg.NewTransactor(pool), Policy: a.Config.Session.Policy(),
	}
	return userCommands{create: commands.NewCreateUser(d), invite: commands.NewCreateInvite(d), users: postgres.NewUsers(pool)}
}

func (a *app) newInvitedUser(t *testing.T, uc userCommands, email, name string) (domain.User, string) {
	t.Helper()
	res, err := uc.create.Execute(ctx, commands.CreateUser{Email: email, Name: name})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	a.ledger.add(&a.ledger.invites, testserver.TokenOf(t, res.Invite.URL))
	return res.User, res.Invite.URL
}

func status(t *testing.T, resp testserver.Response, want int, what string) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s: status = %d, want %d", what, resp.StatusCode, want)
	}
}

func sessionCount(t *testing.T, s *testserver.Server) int {
	t.Helper()
	return count(t, s, `SELECT count(*) FROM sessions`)
}

func TestUsersIntegration(t *testing.T) {
	observability()
	h := &harness{env: testserver.NewEnv(t), ledger: &secretLedger{}, masterKey: testserver.MasterKey(t)}

	// I1: the first start writes one log record that says a link exists. The
	// record has the expiry and never the link or the token.
	t.Run("I1_first_start", func(t *testing.T) {
		a := h.start(t)
		recs := a.logs.SetupPendingRecords(t)
		if len(recs) != 1 {
			t.Fatalf("setup log records = %d, want 1", len(recs))
		}
		if recs[0]["level"] != "WARN" {
			t.Fatalf("level = %v, want WARN", recs[0]["level"])
		}
		if _, ok := recs[0]["expires_at"]; !ok {
			t.Fatal("the record must have the expiry")
		}
		for key := range recs[0] {
			if key == "link" || key == "token" {
				t.Fatalf("the record has the attribute %q", key)
			}
		}
		if text := a.logs.Text(); strings.Contains(text, "/setup?token=") || strings.Contains(text, "token=") {
			t.Fatalf("the log holds a link: %s", text)
		}
		if n := count(t, a.Server, `SELECT count(*) FROM one_time_tokens WHERE purpose = 'setup'`); n != 1 {
			t.Fatalf("setup tokens = %d, want 1", n)
		}
		// The identity manifest was published before the token was made.
		if n := count(t, a.Server, `SELECT count(*) FROM apps a, one_time_tokens t WHERE a.key = 'identity' AND a.published_at <= t.created_at`); n != 1 {
			t.Fatal("the manifest must be published before the setup token")
		}
		// The operator gets the link with the subcommand. The table holds the hash only.
		link := a.setupLink(t)
		if !strings.HasPrefix(link, a.Config.Issuer+"/setup?token=") {
			t.Fatalf("link = %q", link)
		}
		token := testserver.TokenOf(t, link)
		if n := count(t, a.Server, `SELECT count(*) FROM one_time_tokens WHERE token_hash = $1`, domain.HashSecret(token)); n != 1 {
			t.Fatal("the table must hold the hash of the token")
		}
		if n := count(t, a.Server, `SELECT count(*) FROM one_time_tokens WHERE token_hash = $1`, token); n != 0 {
			t.Fatal("the table must not hold the token value")
		}
	})

	// I2: a restart before the setup makes no new token and no new log record.
	t.Run("I2_restart_before_setup", func(t *testing.T) {
		a := h.start(t)
		db := a.DB
		a.Stop()
		b := h.start(t, testserver.WithDB(db))
		if recs := b.logs.SetupPendingRecords(t); len(recs) != 0 {
			t.Fatalf("setup log records after restart = %d, want 0", len(recs))
		}
		if n := count(t, b.Server, `SELECT count(*) FROM one_time_tokens WHERE purpose = 'setup'`); n != 1 {
			t.Fatalf("setup tokens = %d, want 1", n)
		}
	})

	// I2a: setup-link replaces the unused token.
	t.Run("I2a_setup_link", func(t *testing.T) {
		a := h.start(t)
		oldLink := a.setupLink(t)
		newLink, err := services.SetupLink(ctx, a.Config, a.logs.Logger())
		if err != nil {
			t.Fatal(err)
		}
		h.ledger.add(&h.ledger.printed, testserver.TokenOf(t, newLink))
		if strings.Contains(a.logs.Text(), testserver.TokenOf(t, newLink)) {
			t.Fatal("the new link must not be in the log")
		}
		web := a.NewWeb()
		resp, _ := web.Get(t, oldLink)
		status(t, resp, http.StatusBadRequest, "old link")
		resp, _ = web.Get(t, newLink)
		status(t, resp, http.StatusOK, "new link")
		_, resp = a.completeSetup(t, newLink, "admin@example.com", "Admin", adminPassword)
		status(t, resp, http.StatusSeeOther, "setup with the new link")

		// I2b: after the setup, setup-link fails and leaves no token.
		_, err = services.SetupLink(ctx, a.Config, a.logs.Logger())
		if !errors.Is(err, commands.ErrAdminExists) {
			t.Fatalf("setup-link after setup: %v, want ErrAdminExists", err)
		}
		if n := count(t, a.Server, `SELECT count(*) FROM one_time_tokens WHERE purpose = 'setup' AND used_at IS NULL`); n != 0 {
			t.Fatalf("unused setup tokens = %d, want 0", n)
		}
	})

	// I3, I3a, I4, I4b: complete the setup, form errors, link reuse, restart.
	t.Run("I3_I4_setup", func(t *testing.T) {
		a := h.start(t)
		link := a.setupLink(t)
		token := testserver.TokenOf(t, link)
		web := a.NewWeb()

		// I3a: a password mismatch and a short password show the form error and keep the token.
		resp, body := web.PostForm(t, "/setup", url.Values{
			"token": {token}, "email": {"admin@example.com"}, "name": {"Admin"},
			"password": {adminPassword}, "password2": {adminPassword + "x"},
		})
		status(t, resp, http.StatusBadRequest, "mismatch")
		if !strings.Contains(string(body), "The passwords are not the same.") {
			t.Fatalf("mismatch body = %s", body)
		}
		resp, body = web.PostForm(t, "/setup", url.Values{
			"token": {token}, "email": {"admin@example.com"}, "name": {"Admin"},
			"password": {"12345678901"}, "password2": {"12345678901"},
		})
		status(t, resp, http.StatusBadRequest, "short password")
		if !strings.Contains(string(body), "12 to 128 characters") {
			t.Fatalf("short password body = %s", body)
		}
		if n := count(t, a.Server, `SELECT count(*) FROM one_time_tokens WHERE used_at IS NOT NULL`); n != 0 {
			t.Fatal("a form error must not use the token")
		}

		// I3: the setup works and sets the cookie with all flags.
		web, resp = a.completeSetup(t, link, "Admin@Example.com", "Admin", adminPassword)
		status(t, resp, http.StatusSeeOther, "setup")
		if loc := resp.Header.Get("Location"); loc != "/login/done" {
			t.Fatalf("Location = %q", loc)
		}
		var cookie *http.Cookie
		for _, c := range resp.Cookies {
			if c.Name == pages.CookieName {
				cookie = c
			}
		}
		if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode ||
			cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge <= 0 {
			t.Fatalf("cookie = %+v", cookie)
		}
		if n := count(t, a.Server, `SELECT count(*) FROM users u JOIN user_roles r ON r.user_id = u.id
			WHERE u.email = 'admin@example.com' AND u.status = 'active' AND r.app = 'identity' AND r.role = 'admin' AND r.source = 'api'`); n != 1 {
			t.Fatal("the admin user is missing")
		}
		resp, body = web.Get(t, "/login/done")
		status(t, resp, http.StatusOK, "login done")
		if !strings.Contains(string(body), "You are logged in as Admin") {
			t.Fatalf("done body = %s", body)
		}
		assertPageHeaders(t, resp)

		// I4: the link works one time only.
		_, resp = a.completeSetup(t, link, "second@example.com", "Second", adminPassword)
		status(t, resp, http.StatusBadRequest, "link reuse")
		if n := count(t, a.Server, `SELECT count(*) FROM users`); n != 1 {
			t.Fatalf("users = %d, want 1", n)
		}

		// I4b: a restart after the setup makes no token and no log record.
		db := a.DB
		a.Stop()
		b := h.start(t, testserver.WithDB(db))
		if recs := b.logs.SetupPendingRecords(t); len(recs) != 0 {
			t.Fatalf("setup log records after restart = %d", len(recs))
		}
		if n := count(t, b.Server, `SELECT count(*) FROM one_time_tokens WHERE used_at IS NULL`); n != 0 {
			t.Fatalf("unused tokens = %d, want 0", n)
		}
	})

	// I4a: two parallel setup submits with one token.
	t.Run("I4a_parallel_setup", func(t *testing.T) {
		a := h.start(t)
		token := testserver.TokenOf(t, a.setupLink(t))
		a.ledger.add(&a.ledger.passwords, adminPassword)
		var ok, bad atomic.Int32
		var wg sync.WaitGroup
		for _, email := range []string{"one@example.com", "two@example.com"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				web := a.NewWeb()
				resp, _ := web.PostForm(t, "/setup", url.Values{
					"token": {token}, "email": {email}, "name": {"Admin"},
					"password": {adminPassword}, "password2": {adminPassword},
				})
				a.trackSession(web)
				switch resp.StatusCode {
				case http.StatusSeeOther:
					ok.Add(1)
				case http.StatusBadRequest:
					bad.Add(1)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 1 || bad.Load() != 1 {
			t.Fatalf("results = %d ok, %d error page", ok.Load(), bad.Load())
		}
		if n := count(t, a.Server, `SELECT count(*) FROM users`); n != 1 {
			t.Fatalf("users = %d, want 1", n)
		}
	})

	// I5: two instances on a new database make one token.
	t.Run("I5_two_instances", func(t *testing.T) {
		db := h.env.NewDB(t)
		var wg sync.WaitGroup
		apps := make([]*testserver.Server, 2)
		logs := []*testserver.LogCapture{testserver.NewLogCapture(), testserver.NewLogCapture()}
		h.ledger.mu.Lock()
		h.ledger.logs = append(h.ledger.logs, logs...)
		h.ledger.mu.Unlock()
		errs := make([]error, 2)
		for i := range apps {
			wg.Add(1)
			go func() {
				defer wg.Done()
				apps[i], errs[i] = h.env.TryStart(t, testserver.WithDB(db), testserver.WithMasterKey(h.masterKey, "test"), testserver.WithLogger(logs[i].Logger()))
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if n := count(t, apps[0], `SELECT count(*) FROM one_time_tokens WHERE purpose = 'setup'`); n != 1 {
			t.Fatalf("setup tokens = %d, want 1", n)
		}
		total := len(logs[0].SetupPendingRecords(t)) + len(logs[1].SetupPendingRecords(t))
		if total != 1 {
			t.Fatalf("setup log records = %d, want 1", total)
		}
	})

	// A server with an admin, for the invite and login tests.
	adminApp := h.start(t)
	_, resp := adminApp.completeSetup(t, adminApp.setupLink(t), "admin@example.com", "Admin", adminPassword)
	status(t, resp, http.StatusSeeOther, "admin setup")
	uc := adminApp.commands(t)

	// I6: create a user and an invite, then accept the invite.
	t.Run("I6_accept_invite", func(t *testing.T) {
		user, link := adminApp.newInvitedUser(t, uc, "Bob@Example.com", "Bob")
		if user.Email != "bob@example.com" || user.Status != domain.UserInvited {
			t.Fatalf("user = %+v", user)
		}
		web := adminApp.NewWeb()
		resp, _ := web.Get(t, link)
		status(t, resp, http.StatusOK, "invite form")
		assertPageHeaders(t, resp)
		adminApp.ledger.add(&adminApp.ledger.passwords, userPassword)
		resp, _ = web.PostForm(t, "/invite", url.Values{
			"token": {testserver.TokenOf(t, link)}, "password": {userPassword}, "password2": {userPassword},
		})
		adminApp.trackSession(web)
		status(t, resp, http.StatusSeeOther, "accept invite")
		if web.Cookie(pages.CookieName) == "" {
			t.Fatal("no session cookie")
		}
		if n := count(t, adminApp.Server, `SELECT count(*) FROM users WHERE id = $1 AND status = 'active' AND password_hash LIKE '$argon2id$%'`, user.ID); n != 1 {
			t.Fatal("the user must be active with an argon2id hash")
		}
		if n := count(t, adminApp.Server, `SELECT count(*) FROM one_time_tokens WHERE user_id = $1 AND used_at IS NOT NULL`, user.ID); n != 1 {
			t.Fatal("the token must be used")
		}
		if n := count(t, adminApp.Server, `SELECT count(*) FROM sessions WHERE user_id = $1`, user.ID); n != 1 {
			t.Fatal("the user must have a session")
		}
	})

	// I6a: two parallel submits with one invite token.
	t.Run("I6a_parallel_invite", func(t *testing.T) {
		_, link := adminApp.newInvitedUser(t, uc, "para@example.com", "Para")
		var ok, bad atomic.Int32
		var wg sync.WaitGroup
		adminApp.ledger.add(&adminApp.ledger.passwords, userPassword)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				web := adminApp.NewWeb()
				resp, _ := web.PostForm(t, "/invite", url.Values{
					"token": {testserver.TokenOf(t, link)}, "password": {userPassword}, "password2": {userPassword},
				})
				adminApp.trackSession(web)
				switch resp.StatusCode {
				case http.StatusSeeOther:
					ok.Add(1)
				case http.StatusBadRequest:
					bad.Add(1)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 1 || bad.Load() != 1 {
			t.Fatalf("results = %d ok, %d error page", ok.Load(), bad.Load())
		}
	})

	// I6b: a new invite replaces the older unused invite.
	t.Run("I6b_two_invites", func(t *testing.T) {
		user, first := adminApp.newInvitedUser(t, uc, "twice@example.com", "Twice")
		second, err := uc.invite.Execute(ctx, commands.CreateInvite{UserID: user.ID})
		if err != nil {
			t.Fatal(err)
		}
		adminApp.ledger.add(&adminApp.ledger.invites, testserver.TokenOf(t, second.URL))
		web := adminApp.NewWeb()
		resp, _ := web.Get(t, first)
		status(t, resp, http.StatusBadRequest, "first link")
		resp, _ = web.Get(t, second.URL)
		status(t, resp, http.StatusOK, "second link")
	})

	// I6c: an invite form with a password mismatch keeps the token.
	t.Run("I6c_mismatch", func(t *testing.T) {
		_, link := adminApp.newInvitedUser(t, uc, "mismatch@example.com", "Mismatch")
		web := adminApp.NewWeb()
		resp, body := web.PostForm(t, "/invite", url.Values{
			"token": {testserver.TokenOf(t, link)}, "password": {userPassword}, "password2": {userPassword + "x"},
		})
		status(t, resp, http.StatusBadRequest, "mismatch")
		if !strings.Contains(string(body), "The passwords are not the same.") {
			t.Fatalf("body = %s", body)
		}
		resp, _ = web.Get(t, link)
		status(t, resp, http.StatusOK, "link after the error")
	})

	// I6d: a disabled user cannot use the invite link.
	t.Run("I6d_disabled_user", func(t *testing.T) {
		user, link := adminApp.newInvitedUser(t, uc, "disabled@example.com", "Disabled")
		before := sessionCount(t, adminApp.Server)
		if err := uc.users.SetStatus(ctx, user.ID, domain.UserDisabled, time.Now()); err != nil {
			t.Fatal(err)
		}
		web := adminApp.NewWeb()
		resp, _ := web.PostForm(t, "/invite", url.Values{
			"token": {testserver.TokenOf(t, link)}, "password": {userPassword}, "password2": {userPassword},
		})
		status(t, resp, http.StatusBadRequest, "submit")
		if n := count(t, adminApp.Server, `SELECT count(*) FROM users WHERE id = $1 AND status = 'disabled' AND password_hash IS NULL`, user.ID); n != 1 {
			t.Fatal("the user must stay disabled with no password")
		}
		if sessionCount(t, adminApp.Server) != before || web.Cookie(pages.CookieName) != "" {
			t.Fatal("no session must be made")
		}
		if _, err := uc.invite.Execute(ctx, commands.CreateInvite{UserID: user.ID}); !errors.Is(err, commands.ErrUserDisabled) {
			t.Fatalf("CreateInvite for a disabled user: %v", err)
		}
	})

	// I6e: an old invite token of an active user does not change the user.
	t.Run("I6e_old_token_of_active_user", func(t *testing.T) {
		user, first := adminApp.newInvitedUser(t, uc, "bob2@example.com", "Bob Two")
		// Keep the first token, and add a second token with no delete of the first.
		pool := adminApp.Pool(t)
		second, value, err := newInviteRow(t, pool, user.ID)
		if err != nil {
			t.Fatal(err)
		}
		_ = second
		adminApp.ledger.add(&adminApp.ledger.invites, value)
		web := adminApp.NewWeb()
		adminApp.ledger.add(&adminApp.ledger.passwords, userPassword)
		resp, _ := web.PostForm(t, "/invite", url.Values{
			"token": {value}, "password": {userPassword}, "password2": {userPassword},
		})
		adminApp.trackSession(web)
		status(t, resp, http.StatusSeeOther, "accept with the second token")
		var hashBefore string
		if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, user.ID).Scan(&hashBefore); err != nil {
			t.Fatal(err)
		}
		sessionsBefore := count(t, adminApp.Server, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, user.ID)

		if _, err := uc.invite.Execute(ctx, commands.CreateInvite{UserID: user.ID}); !errors.Is(err, commands.ErrUserNotInvited) {
			t.Fatalf("CreateInvite for an active user: %v", err)
		}
		other := adminApp.NewWeb()
		resp, _ = other.PostForm(t, "/invite", url.Values{
			"token": {testserver.TokenOf(t, first)}, "password": {"another password 99999"}, "password2": {"another password 99999"},
		})
		status(t, resp, http.StatusBadRequest, "old token")
		var hashAfter string
		if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, user.ID).Scan(&hashAfter); err != nil {
			t.Fatal(err)
		}
		if hashAfter != hashBefore {
			t.Fatal("the password hash must not change")
		}
		if n := count(t, adminApp.Server, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, user.ID); n != sessionsBefore {
			t.Fatal("the sessions must not change")
		}
		if n := count(t, adminApp.Server, `SELECT count(*) FROM one_time_tokens WHERE token_hash = $1 AND used_at IS NULL`, domain.HashSecret(testserver.TokenOf(t, first))); n != 1 {
			t.Fatal("the rolled back token must stay unused")
		}
	})

	// I7: an expired invite.
	t.Run("I7_expired_invite", func(t *testing.T) {
		user, link := adminApp.newInvitedUser(t, uc, "expired@example.com", "Expired")
		if _, err := adminApp.Pool(t).Exec(ctx, `UPDATE one_time_tokens SET expires_at = now() - interval '1 minute' WHERE user_id = $1`, user.ID); err != nil {
			t.Fatal(err)
		}
		web := adminApp.NewWeb()
		resp, _ := web.Get(t, link)
		status(t, resp, http.StatusBadRequest, "form")
		resp, _ = web.PostForm(t, "/invite", url.Values{
			"token": {testserver.TokenOf(t, link)}, "password": {userPassword}, "password2": {userPassword},
		})
		status(t, resp, http.StatusBadRequest, "submit")
		if n := count(t, adminApp.Server, `SELECT count(*) FROM users WHERE id = $1 AND status = 'invited'`, user.ID); n != 1 {
			t.Fatal("the user must stay invited")
		}
	})

	// I8, I9: login, logout, and the session change at a login.
	t.Run("I8_I9_login_logout", func(t *testing.T) {
		web := adminApp.NewWeb()
		adminApp.ledger.add(&adminApp.ledger.passwords, adminPassword)
		resp, _ := web.PostForm(t, "/login", url.Values{"email": {"ADMIN@example.com"}, "password": {adminPassword}})
		adminApp.trackSession(web)
		status(t, resp, http.StatusSeeOther, "login")
		first := web.Cookie(pages.CookieName)
		resp, _ = web.Get(t, "/login/done")
		status(t, resp, http.StatusOK, "done")

		// I9 (issue 4): a login of the same user with a session cookie keeps the
		// session and gives a new cookie value. The old value stops.
		resp, _ = web.PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {adminPassword}})
		adminApp.trackSession(web)
		status(t, resp, http.StatusSeeOther, "second login")
		second := web.Cookie(pages.CookieName)
		if second == first {
			t.Fatal("the session must change at a login")
		}
		old := adminApp.NewWeb()
		old.SetCookie(pages.CookieName, first)
		resp, _ = old.Get(t, "/login/done")
		status(t, resp, http.StatusSeeOther, "old session")

		resp, _ = web.PostForm(t, "/logout", url.Values{})
		status(t, resp, http.StatusSeeOther, "logout")
		if web.Cookie(pages.CookieName) != "" {
			t.Fatal("logout must clear the cookie")
		}
		again := adminApp.NewWeb()
		again.SetCookie(pages.CookieName, second)
		resp, _ = again.Get(t, "/login/done")
		status(t, resp, http.StatusSeeOther, "revoked session")
		if n := count(t, adminApp.Server, `SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL`); n < 1 {
			t.Fatalf("revoked sessions = %d", n)
		}
	})

	// A login with return_to follows only a safe local path.
	t.Run("login_return_to", func(t *testing.T) {
		for target, want := range map[string]string{
			"/a?b=c": "/a?b=c", "//evil.example": "/login/done", "https://evil.example": "/login/done", "/%5Cevil.example": "/login/done",
		} {
			web := adminApp.NewWeb()
			resp, _ := web.PostForm(t, "/login", url.Values{
				"email": {"admin@example.com"}, "password": {adminPassword}, "return_to": {target},
			})
			adminApp.trackSession(web)
			status(t, resp, http.StatusSeeOther, "login "+target)
			if loc := resp.Header.Get("Location"); loc != want {
				t.Fatalf("return_to %q: Location = %q, want %q", target, loc, want)
			}
		}
	})

	// I10: a cross-site POST gives 403 and changes no session.
	t.Run("I10_cross_site", func(t *testing.T) {
		before := sessionCount(t, adminApp.Server)
		web := adminApp.NewWeb()
		web.Header.Set("Sec-Fetch-Site", "cross-site")
		for _, path := range []string{"/login", "/setup", "/invite", "/logout"} {
			resp, _ := web.PostForm(t, path, url.Values{
				"email": {"admin@example.com"}, "password": {adminPassword}, "password2": {adminPassword}, "token": {"x"},
			})
			status(t, resp, http.StatusForbidden, "POST "+path)
		}
		if sessionCount(t, adminApp.Server) != before {
			t.Fatal("a cross-site request must not change a session")
		}
		// The logout of a cross-site request must not revoke the session.
		adminApp.completeSetupLogin(t)
	})

	// I10a: the failure limit of an email. The limit stops the correct password too.
	t.Run("I10a_failure_limit", func(t *testing.T) {
		limitedBefore := loginCount(t, "limited")
		adminApp.ledger.add(&adminApp.ledger.passwords, adminPassword)
		runsBefore := passwordRuns(t)
		for range 5 {
			web := adminApp.NewWeb()
			resp, body := web.PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {"wrong password 123456"}})
			status(t, resp, http.StatusUnauthorized, "failed login")
			if !strings.Contains(string(body), "Email or password is not correct") {
				t.Fatalf("body = %s", body)
			}
		}
		if got := passwordRuns(t) - runsBefore; got != 5 {
			t.Fatalf("hashes after 5 failed logins = %d, want 5", got)
		}
		runsBefore = passwordRuns(t)
		web := adminApp.NewWeb()
		resp, body := web.PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {"wrong password 123456"}})
		status(t, resp, http.StatusTooManyRequests, "attempt 6")
		if !strings.Contains(string(body), "Too many attempts. Try again later.") {
			t.Fatalf("body = %s", body)
		}
		resp, _ = web.PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {adminPassword}})
		status(t, resp, http.StatusTooManyRequests, "correct password of a limited email")
		if web.Cookie(pages.CookieName) != "" {
			t.Fatal("a limited login must not make a session")
		}
		if got := loginCount(t, "limited") - limitedBefore; got != 2 {
			t.Fatalf("limited logins = %d, want 2", got)
		}
		// R5: the limit stops both requests before the hash.
		if got := passwordRuns(t) - runsBefore; got != 0 {
			t.Fatalf("hashes for the limited logins = %d, want 0", got)
		}
	})

	// I10c (R6): parallel wrong passwords for one email cannot pass the limit.
	// The test uses a new server, so that the counters of the other tests do not
	// count.
	t.Run("I10c_parallel_login_limit", func(t *testing.T) {
		_, a := h.startOwnValkey(t)
		_, resp := a.completeSetup(t, a.setupLink(t), "admin@example.com", "Admin", adminPassword)
		status(t, resp, http.StatusSeeOther, "setup")
		runsBefore := passwordRuns(t)
		const parallel = 40
		codes := make([]int, parallel)
		var wg sync.WaitGroup
		for i := range parallel {
			wg.Go(func() {
				r, _ := a.NewWeb().PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {"wrong password 123456"}})
				codes[i] = r.StatusCode
			})
		}
		wg.Wait()
		var unauthorized, limited int
		for _, c := range codes {
			switch c {
			case http.StatusUnauthorized:
				unauthorized++
			case http.StatusTooManyRequests:
				limited++
			default:
				t.Fatalf("status = %d, want 401 or 429", c)
			}
		}
		if unauthorized != 5 || limited != parallel-5 {
			t.Fatalf("401 = %d and 429 = %d, want 5 and %d", unauthorized, limited, parallel-5)
		}
		if got := passwordRuns(t) - runsBefore; got != 5 {
			t.Fatalf("hashes = %d, want 5", got)
		}
		r, _ := a.NewWeb().PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {adminPassword}})
		status(t, r, http.StatusTooManyRequests, "correct password after the burst")
	})

	// I10i (R20): good logins from one IP never reach the IP limit. Failures do.
	t.Run("I10i_good_logins_do_not_fill_ip_limit", func(t *testing.T) {
		_, a := h.startOwnValkey(t)
		_, resp := a.completeSetup(t, a.setupLink(t), "admin@example.com", "Admin", adminPassword)
		status(t, resp, http.StatusSeeOther, "setup")
		for i := range 60 {
			r, _ := a.NewWeb().PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {adminPassword}})
			if r.StatusCode != http.StatusSeeOther {
				t.Fatalf("good login %d: status = %d, want 303", i+1, r.StatusCode)
			}
		}
		// Each wrong login uses a new email, so only the IP limit of 50 can stop it.
		for i := range 50 {
			r, _ := a.NewWeb().PostForm(t, "/login", url.Values{"email": {fmt.Sprintf("nobody%d@example.com", i)}, "password": {"wrong password 123456"}})
			if r.StatusCode != http.StatusUnauthorized {
				t.Fatalf("failure %d: status = %d, want 401", i+1, r.StatusCode)
			}
		}
		r, _ := a.NewWeb().PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {adminPassword}})
		status(t, r, http.StatusTooManyRequests, "login 51 after 50 failures from one IP")
	})

	// I10f (R7): a bad token gives the error page and runs no hash.
	t.Run("I10f_bad_token_no_hash", func(t *testing.T) {
		runsBefore := passwordRuns(t)
		for _, path := range []string{"/setup", "/invite"} {
			web := adminApp.NewWeb()
			resp, body := web.PostForm(t, path, url.Values{
				"token": {"nope"}, "email": {"x@example.com"}, "name": {"X"},
				"password": {"a valid password 99"}, "password2": {"a valid password 99"},
			})
			status(t, resp, http.StatusBadRequest, "POST "+path+" with a bad token")
			if strings.Contains(string(body), "a valid password 99") {
				t.Fatal("the page must not show the password")
			}
		}
		if got := passwordRuns(t) - runsBefore; got != 0 {
			t.Fatalf("hashes for bad tokens = %d, want 0", got)
		}
	})

	// I10g (R9): a valid setup token cannot make a second admin.
	t.Run("I10g_setup_with_admin", func(t *testing.T) {
		pool := adminApp.Pool(t)
		value, hash, err := domain.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO one_time_tokens (token_hash, purpose, expires_at, created_at)
			VALUES ($1, 'setup', now() + interval '1 hour', now())`, hash); err != nil {
			t.Fatal(err)
		}
		web := adminApp.NewWeb()
		resp, _ := web.PostForm(t, "/setup", url.Values{
			"token": {value}, "email": {"second@example.com"}, "name": {"Second"},
			"password": {userPassword}, "password2": {userPassword},
		})
		adminApp.trackSession(web)
		status(t, resp, http.StatusBadRequest, "setup with an admin")
		if n := count(t, adminApp.Server, `SELECT count(*) FROM users WHERE email = 'second@example.com'`); n != 0 {
			t.Fatalf("second users = %d, want 0", n)
		}
		if n := count(t, adminApp.Server, `SELECT count(*) FROM one_time_tokens WHERE token_hash = $1 AND used_at IS NULL`, hash); n != 1 {
			t.Fatal("the token must stay unused")
		}
		if n := count(t, adminApp.Server, `SELECT count(*) FROM user_roles WHERE app = 'identity' AND role = 'admin'`); n != 1 {
			t.Fatalf("admin role rows = %d, want 1", n)
		}
	})

	// I10h (R8): CreateInvite and AcceptInvite for one user, in parallel, use
	// one lock order and cannot deadlock.
	t.Run("I10h_invite_lock_order", func(t *testing.T) {
		const workers, rounds = 8, 30
		var wg sync.WaitGroup
		var failures atomic.Int64
		for w := range workers {
			wg.Go(func() {
				for r := range rounds {
					email := fmt.Sprintf("lock-%d-%d@example.com", w, r)
					res, err := uc.create.Execute(ctx, commands.CreateUser{Email: email, Name: "Lock"})
					if err != nil {
						t.Errorf("create user: %v", err)
						failures.Add(1)
						return
					}
					adminApp.ledger.add(&adminApp.ledger.invites, testserver.TokenOf(t, res.Invite.URL))
					var inner sync.WaitGroup
					inner.Go(func() {
						if _, err := uc.invite.Execute(ctx, commands.CreateInvite{UserID: res.User.ID}); err != nil && !errors.Is(err, commands.ErrUserNotInvited) {
							t.Errorf("create invite: %v", err)
							failures.Add(1)
						}
					})
					inner.Go(func() {
						web := adminApp.NewWeb()
						adminApp.ledger.add(&adminApp.ledger.passwords, userPassword)
						resp, _ := web.PostForm(t, "/invite", url.Values{
							"token": {testserver.TokenOf(t, res.Invite.URL)}, "password": {userPassword}, "password2": {userPassword},
						})
						adminApp.trackSession(web)
						if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusBadRequest {
							t.Errorf("accept invite: status = %d, want 303 or 400", resp.StatusCode)
							failures.Add(1)
						}
					})
					inner.Wait()
				}
			})
		}
		wg.Wait()
		if failures.Load() != 0 {
			t.Fatalf("%d failures", failures.Load())
		}
	})

	// I11: the retention jobs delete old tokens and sessions.
	t.Run("I11_retention", func(t *testing.T) {
		a := h.start(t)
		db := a.DB
		pool := a.Pool(t)
		seedRetention(t, pool)
		a.Stop()
		fireOnce := func(d time.Duration) <-chan time.Time {
			if d <= time.Hour/10 {
				c := make(chan time.Time, 1)
				c <- time.Now()
				return c
			}
			return nil
		}
		b := h.start(t, testserver.WithDB(db), testserver.WithRetentionAfter(fireOnce),
			testserver.WithConfigure(func(c *config.Config) {
				c.Retention.Tokens = retention.Config{Period: 24 * time.Hour, Interval: time.Hour, BatchSize: 100}
				c.Retention.Sessions = retention.Config{Period: 24 * time.Hour, Interval: time.Hour, BatchSize: 100}
			}))
		deadline := time.Now().Add(15 * time.Second)
		for {
			tokens := count(t, b.Server, `SELECT count(*) FROM one_time_tokens WHERE token_hash LIKE 'ret-%'`)
			sessions := count(t, b.Server, `SELECT count(*) FROM sessions WHERE token_hash LIKE 'ret-%'`)
			if tokens == 1 && sessions == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("after the retention job: tokens = %d, sessions = %d, want 1 and 1", tokens, sessions)
			}
			time.Sleep(200 * time.Millisecond)
		}
	})

	// I10b: Valkey stopped during a login gives 503 and no session.
	t.Run("I10b_valkey_down", func(t *testing.T) {
		vk, a := h.startOwnValkey(t)
		s := a.Server
		_, resp := a.completeSetup(t, a.setupLink(t), "admin@example.com", "Admin", adminPassword)
		status(t, resp, http.StatusSeeOther, "setup")
		before := sessionCount(t, s)
		if err := vk.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		web := a.NewWeb()
		a.ledger.add(&a.ledger.passwords, adminPassword)
		resp, _ = web.PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {adminPassword}})
		status(t, resp, http.StatusServiceUnavailable, "login with Valkey down")
		if sessionCount(t, s) != before || web.Cookie(pages.CookieName) != "" {
			t.Fatal("no session must be made")
		}
	})

	// I12: no log record and no span holds a secret.
	t.Run("I12_no_secrets_in_telemetry", func(t *testing.T) {
		var texts []string
		h.ledger.mu.Lock()
		defer h.ledger.mu.Unlock()
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
				spans += e.Name + "\n"
				for _, a := range e.Attributes {
					spans += string(a.Key) + "=" + a.Value.String() + "\n"
				}
			}
		}
		if len(h.ledger.setups) == 0 || len(h.ledger.invites) == 0 || len(h.ledger.sessions) == 0 {
			t.Fatal("the ledger has no secrets, so the test checks nothing")
		}
		for _, secret := range append(append(append([]string{}, h.ledger.passwords...), h.ledger.sessions...), h.ledger.invites...) {
			for _, text := range texts {
				if strings.Contains(text, secret) {
					t.Fatalf("a log record holds the secret %q", secret[:8])
				}
			}
			if strings.Contains(spans, secret) {
				t.Fatalf("a span holds the secret %q", secret[:8])
			}
		}
		for _, secret := range h.ledger.printed {
			for _, text := range texts {
				if strings.Contains(text, secret) {
					t.Fatal("the log holds a link from setup-link")
				}
			}
			if strings.Contains(spans, secret) {
				t.Fatal("a span holds a setup token")
			}
		}
		for _, secret := range h.ledger.setups {
			if strings.Contains(spans, secret) {
				t.Fatal("a span holds a setup token")
			}
			total := 0
			for _, text := range texts {
				total += strings.Count(text, secret)
			}
			if total != 0 {
				t.Fatalf("a setup token is in %d log records, want 0", total)
			}
		}
	})
}

// completeSetupLogin is a helper that does nothing more than log in as the
// admin. It checks that the logout of the cross-site test did not revoke the
// session of the browser.
func (a *app) completeSetupLogin(t *testing.T) (*testserver.Web, testserver.Response) {
	t.Helper()
	web := a.NewWeb()
	resp, _ := web.PostForm(t, "/login", url.Values{"email": {"admin@example.com"}, "password": {adminPassword}})
	a.trackSession(web)
	status(t, resp, http.StatusSeeOther, "login")
	web.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, _ = web.PostForm(t, "/logout", url.Values{})
	status(t, resp, http.StatusForbidden, "cross-site logout")
	web.Header.Del("Sec-Fetch-Site")
	resp, _ = web.Get(t, "/login/done")
	status(t, resp, http.StatusOK, "session after the cross-site logout")
	return web, resp
}

// newInviteRow adds an invite token for a user without a delete of the older
// tokens.
func newInviteRow(t *testing.T, pool *pgxpool.Pool, userID string) (string, string, error) {
	t.Helper()
	value, hash, err := domain.NewSecret()
	if err != nil {
		return "", "", err
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO one_time_tokens (token_hash, purpose, user_id, expires_at, created_at)
		VALUES ($1, 'invite', $2, now() + interval '1 hour', now())`, hash, userID)
	return hash, value, err
}

// seedRetention adds old and new tokens and sessions. The names of the old rows
// start with ret-.
func seedRetention(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var userID = "00000000-0000-4000-8000-0000000000aa"
	stmts := []string{
		`INSERT INTO users (id, email, name, status, created_at, updated_at) VALUES ('` + userID + `', 'ret@example.com', 'Ret', 'active', now(), now())`,
		`INSERT INTO one_time_tokens (token_hash, purpose, expires_at, created_at) VALUES ('ret-old-expired', 'setup', now() - interval '10 days', now() - interval '11 days')`,
		`INSERT INTO one_time_tokens (token_hash, purpose, expires_at, used_at, created_at) VALUES ('ret-old-used', 'setup', now() - interval '5 days', now() - interval '9 days', now() - interval '10 days')`,
		`INSERT INTO one_time_tokens (token_hash, purpose, expires_at, created_at) VALUES ('ret-new-token', 'setup', now() - interval '1 hour', now() - interval '2 hours')`,
		`INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at) VALUES
			('00000000-0000-4000-8000-0000000000b1', '` + userID + `', 'ret-old-session', now() - interval '12 days', now() - interval '12 days', now() - interval '11 days', now() - interval '10 days')`,
		`INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at, revoked_at) VALUES
			('00000000-0000-4000-8000-0000000000b2', '` + userID + `', 'ret-old-revoked', now() - interval '12 days', now() - interval '12 days', now() + interval '1 day', now() + interval '5 days', now() - interval '9 days')`,
		`INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, expires_at) VALUES
			('00000000-0000-4000-8000-0000000000b3', '` + userID + `', 'ret-new-session', now() - interval '3 hours', now() - interval '3 hours', now() - interval '2 hours', now() - interval '1 hour')`,
	}
	for _, q := range stmts {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
}

// assertPageHeaders checks the security headers of a page response.
func assertPageHeaders(t *testing.T, resp testserver.Response) {
	t.Helper()
	csp := resp.Header.Get("Content-Security-Policy")
	for _, part := range []string{"default-src 'none'", "style-src 'self'", "form-action 'self'", "base-uri 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, part) {
			t.Fatalf("CSP %q lacks %q", csp, part)
		}
	}
	for name, want := range map[string]string{
		"Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
	} {
		if got := resp.Header.Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}
