package commands_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

type env struct {
	users    *mock.Users
	roles    *mock.UserRoles
	tokens   *mock.OneTimeTokens
	sessions *mock.Sessions
	hasher   *mock.Hasher
	limiter  *mock.Limiter
	logins   *mock.Events
	now      time.Time
}

func newEnv() *env {
	u := mock.NewUsers()
	return &env{
		users: u, roles: mock.NewUserRoles(u), tokens: mock.NewOneTimeTokens(), sessions: mock.NewSessions(),
		hasher: &mock.Hasher{}, limiter: mock.NewLimiter(), logins: &mock.Events{}, now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
	}
}

func (e *env) clock() time.Time { return e.now }

var policy = domain.SessionPolicy{IdleTimeout: time.Hour, AbsoluteTimeout: 24 * time.Hour}

func (e *env) login() *commands.LoginCommand {
	c, err := commands.NewLogin(commands.LoginDeps{
		Users: e.users, Session: e.sessions, Hasher: e.hasher, Limiter: e.limiter,
		Limits: commands.LoginLimits{MaxFailuresPerEmail: 3, MaxFailuresPerIP: 50}, Policy: policy, Now: e.clock,
		Tx: mock.Tx{}, Audit: e.logins,
	})
	if err != nil {
		panic(err)
	}
	return c
}

func (e *env) invites() commands.InviteDeps {
	return commands.InviteDeps{
		Issuer: "https://id.example.com", TTL: time.Hour, Tokens: e.tokens, Users: e.users, Session: e.sessions,
		Hasher: e.hasher, Tx: mock.Tx{}, Audit: &mock.Events{}, Policy: policy, Now: e.clock,
	}
}

func (e *env) setup() commands.SetupDeps {
	return commands.SetupDeps{
		Issuer: "https://id.example.com", TTL: time.Hour, Tokens: e.tokens, Roles: e.roles, Users: e.users,
		Session: e.sessions, Hasher: e.hasher, Tx: mock.Tx{}, Audit: &mock.Events{}, Policy: policy, Now: e.clock,
	}
}

func (e *env) addUser(id, email string, status domain.UserStatus, password string) {
	hash := ""
	if password != "" {
		hash = "fake$" + password
	}
	e.users.Rows[id] = domain.User{ID: id, Email: email, Name: id, Status: status, PasswordHash: hash}
}

var ctx = context.Background()

// U6: all failure kinds give the same error, and the hasher runs one time for each.
func TestU6_LoginFailuresLookAlike(t *testing.T) {
	e := newEnv()
	e.addUser("active", "active@example.com", domain.UserActive, "right password 1")
	e.addUser("invited", "invited@example.com", domain.UserInvited, "")
	e.addUser("disabled", "disabled@example.com", domain.UserDisabled, "right password 1")
	cmd := e.login()
	cases := map[string]commands.Login{
		"unknown email":  {Email: "nobody@example.com", Password: "right password 1", IP: "1.1.1.1"},
		"wrong password": {Email: "active@example.com", Password: "wrong password 1", IP: "1.1.1.2"},
		"invited user":   {Email: "invited@example.com", Password: "right password 1", IP: "1.1.1.3"},
		"disabled user":  {Email: "disabled@example.com", Password: "right password 1", IP: "1.1.1.4"},
	}
	for name, in := range cases {
		before := e.hasher.Runs()
		_, err := cmd.Execute(ctx, in)
		if !errors.Is(err, commands.ErrBadCredentials) {
			t.Fatalf("%s: err = %v, want ErrBadCredentials", name, err)
		}
		if got := e.hasher.Runs() - before; got != 1 {
			t.Fatalf("%s: hasher runs = %d, want 1", name, got)
		}
	}
	if len(e.sessions.Rows) != 0 {
		t.Fatal("a failed login must not make a session")
	}
}

// U6a: a counter at the limit gives the limit error and no hash.
func TestU6a_LoginLimited(t *testing.T) {
	e := newEnv()
	e.addUser("active", "active@example.com", domain.UserActive, "right password 1")
	e.limiter.Emails["active@example.com"] = 3
	_, err := e.login().Execute(ctx, commands.Login{Email: "active@example.com", Password: "right password 1", IP: "1.1.1.1"})
	if !errors.Is(err, commands.ErrTooManyAttempts) {
		t.Fatalf("err = %v, want ErrTooManyAttempts", err)
	}
	if e.hasher.Runs() != 0 {
		t.Fatal("the hasher must not run")
	}
	e.limiter.Emails = map[string]int64{}
	e.limiter.IPs["9.9.9.9"] = 50
	if _, err := e.login().Execute(ctx, commands.Login{Email: "active@example.com", Password: "right password 1", IP: "9.9.9.9"}); !errors.Is(err, commands.ErrTooManyAttempts) {
		t.Fatalf("IP limit: err = %v", err)
	}
}

// U6b: an unknown email increments both counters.
func TestU6b_UnknownEmailCounts(t *testing.T) {
	e := newEnv()
	_, _ = e.login().Execute(ctx, commands.Login{Email: "Nobody@Example.com", Password: "x", IP: "1.1.1.1"})
	if e.limiter.Emails["nobody@example.com"] != 1 || e.limiter.IPs["1.1.1.1"] != 1 {
		t.Fatalf("counters = %v %v", e.limiter.Emails, e.limiter.IPs)
	}
}

// U6c: a success deletes the email counter and takes back its own attempt from
// the IP counter. The IP counter keeps the failures only.
func TestU6c_SuccessResetsEmailCounter(t *testing.T) {
	e := newEnv()
	e.addUser("active", "active@example.com", domain.UserActive, "right password 1")
	cmd := e.login()
	for range 2 {
		_, _ = cmd.Execute(ctx, commands.Login{Email: "active@example.com", Password: "wrong", IP: "1.1.1.1"})
	}
	if _, err := cmd.Execute(ctx, commands.Login{Email: "active@example.com", Password: "right password 1", IP: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.limiter.Emails["active@example.com"]; ok {
		t.Fatal("the email counter must be deleted")
	}
	if e.limiter.IPs["1.1.1.1"] != 2 {
		t.Fatalf("IP counter = %d, want 2 failures", e.limiter.IPs["1.1.1.1"])
	}
}

// U6g (R20): good logins leave the IP counter at 0, and a failed decrease does
// not stop the login.
func TestU6g_GoodLoginsDoNotCountForIP(t *testing.T) {
	e := newEnv()
	e.addUser("active", "active@example.com", domain.UserActive, "right password 1")
	cmd := e.login()
	for range 5 {
		if _, err := cmd.Execute(ctx, commands.Login{Email: "active@example.com", Password: "right password 1", IP: "1.1.1.1"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.limiter.IPs["1.1.1.1"]; got != 0 {
		t.Fatalf("IP counter = %d, want 0", got)
	}
	e.limiter.SuccessErr = errors.New("down")
	if _, err := cmd.Execute(ctx, commands.Login{Email: "active@example.com", Password: "right password 1", IP: "1.1.1.1"}); err != nil {
		t.Fatalf("login with a failed decrease = %v, want success", err)
	}
}

func TestLoginLimiterDownFailsClosed(t *testing.T) {
	e := newEnv()
	e.limiter.Err = errors.New("down")
	_, err := e.login().Execute(ctx, commands.Login{Email: "a@example.com", Password: "x", IP: "1.1.1.1"})
	if !errors.Is(err, commands.ErrLimiterUnavailable) || e.hasher.Runs() != 0 {
		t.Fatalf("err = %v, runs = %d", err, e.hasher.Runs())
	}
}

func TestLoginRehashAndPreviousSession(t *testing.T) {
	e := newEnv()
	e.addUser("active", "active@example.com", domain.UserActive, "right password 1")
	e.hasher.Rehash = true
	first, err := e.login().Execute(ctx, commands.Login{Email: "active@example.com", Password: "right password 1", IP: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.login().Execute(ctx, commands.Login{Email: "active@example.com", Password: "right password 1", IP: "1.1.1.1", PreviousToken: first.Token})
	if err != nil {
		t.Fatal(err)
	}
	// Issue 4: a login of the same user keeps the session. The cookie value
	// changes and the old value stops.
	if second.Token == first.Token || second.SessionID != first.SessionID {
		t.Fatal("a same-user login keeps the session and changes the cookie value")
	}
	if _, err := e.sessions.GetByTokenHash(ctx, domain.HashSecret(first.Token)); err == nil {
		t.Fatal("the old cookie value must stop")
	}
	if e.hasher.Hashes == 0 {
		t.Fatal("a hash with old parameters must be replaced")
	}
}

// U7: a valid setup token exists, so no new token is made.
func TestU7_EnsureSetupToken(t *testing.T) {
	e := newEnv()
	cmd := commands.NewEnsureSetupToken(e.setup())
	first, err := cmd.Execute(ctx, commands.EnsureSetupToken{})
	if err != nil || first.Link.URL == "" {
		t.Fatalf("first: %v %+v", err, first)
	}
	second, err := cmd.Execute(ctx, commands.EnsureSetupToken{})
	if err != nil || second.Link.URL != "" || len(e.tokens.Rows) != 1 {
		t.Fatalf("second: %v %+v, tokens = %d", err, second, len(e.tokens.Rows))
	}
	// After the expiry the next start makes a new token.
	e.now = e.now.Add(2 * time.Hour)
	third, err := cmd.Execute(ctx, commands.EnsureSetupToken{})
	if err != nil || third.Link.URL == "" {
		t.Fatalf("third: %v %+v", err, third)
	}
	// With an active admin, no token is made.
	e.addUser("admin", "admin@example.com", domain.UserActive, "x")
	_, _ = e.roles.Assign(ctx, "admin", domain.AdminRole, domain.AssignmentAPI)
	e.now = e.now.Add(2 * time.Hour)
	fourth, err := cmd.Execute(ctx, commands.EnsureSetupToken{})
	if err != nil || fourth.Link.URL != "" {
		t.Fatalf("fourth: %v %+v", err, fourth)
	}
	if _, err := commands.NewReplaceSetupToken(e.setup()).Execute(ctx, commands.ReplaceSetupToken{}); !errors.Is(err, commands.ErrAdminExists) {
		t.Fatalf("replace with an admin: %v", err)
	}
}

// U8: sessions expire by idle time and by absolute time.
func TestU8_SessionExpiry(t *testing.T) {
	start := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	s := policy.NewSession("u", start, nil)
	if !s.Valid(start.Add(59 * time.Minute)) {
		t.Fatal("the session must be valid before the idle expiry")
	}
	if s.Valid(start.Add(61 * time.Minute)) {
		t.Fatal("the session must end at the idle expiry")
	}
	// A touch moves the idle expiry, but not past the absolute expiry.
	late := start.Add(23*time.Hour + 30*time.Minute)
	if got := policy.IdleExpiry(s, late); !got.Equal(s.ExpiresAt) {
		t.Fatalf("idle expiry = %v, want the absolute expiry %v", got, s.ExpiresAt)
	}
	s.IdleExpiresAt = s.ExpiresAt
	if s.Valid(start.Add(25 * time.Hour)) {
		t.Fatal("the session must end at the absolute expiry")
	}
	rev := start
	s.RevokedAt = &rev
	if s.Valid(start.Add(time.Minute)) {
		t.Fatal("a revoked session is not valid")
	}
}

// U8a: SessionFromCookie rejects the session of a disabled user.
func TestU8a_SessionOfDisabledUser(t *testing.T) {
	e := newEnv()
	e.addUser("u", "u@example.com", domain.UserActive, "right password 1")
	issued, err := e.login().Execute(ctx, commands.Login{Email: "u@example.com", Password: "right password 1", IP: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	q := queries.NewSessionFromCookie(e.sessions, e.users, e.clock)
	if _, err := q.Execute(ctx, queries.SessionFromCookie{Token: issued.Token}); err != nil {
		t.Fatalf("active user: %v", err)
	}
	_ = e.users.SetStatus(ctx, "u", domain.UserDisabled, e.now)
	if _, err := q.Execute(ctx, queries.SessionFromCookie{Token: issued.Token}); !errors.Is(err, queries.ErrNoSession) {
		t.Fatalf("disabled user: %v, want ErrNoSession", err)
	}
	if _, err := q.Execute(ctx, queries.SessionFromCookie{Token: "unknown"}); !errors.Is(err, queries.ErrNoSession) {
		t.Fatalf("unknown token: %v", err)
	}
}

func TestTouchSessionOncePerMinute(t *testing.T) {
	e := newEnv()
	e.addUser("u", "u@example.com", domain.UserActive, "right password 1")
	issued, _ := e.login().Execute(ctx, commands.Login{Email: "u@example.com", Password: "right password 1", IP: "1.1.1.1"})
	touch := commands.NewTouchSession(commands.LoginDeps{Session: e.sessions, Policy: policy, Now: e.clock})
	s, _ := e.sessions.GetByTokenHash(ctx, domain.HashSecret(issued.Token))
	e.now = e.now.Add(30 * time.Second)
	_ = touch.Execute(ctx, commands.TouchSession{Session: s})
	if e.sessions.Touches != 0 {
		t.Fatal("a touch within a minute must not write")
	}
	e.now = e.now.Add(31 * time.Second)
	_ = touch.Execute(ctx, commands.TouchSession{Session: s})
	if e.sessions.Touches != 1 {
		t.Fatalf("touches = %d, want 1", e.sessions.Touches)
	}
}

// U13 and U13a: an invite is only for an invited user.
func TestU13_CreateInvite(t *testing.T) {
	e := newEnv()
	e.addUser("disabled", "d@example.com", domain.UserDisabled, "")
	e.addUser("active", "a@example.com", domain.UserActive, "right password 1")
	e.addUser("invited", "i@example.com", domain.UserInvited, "")
	cmd := commands.NewCreateInvite(e.invites())

	if _, err := cmd.Execute(ctx, commands.CreateInvite{UserID: "disabled"}); !errors.Is(err, commands.ErrUserDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	if _, err := cmd.Execute(ctx, commands.CreateInvite{UserID: "active"}); !errors.Is(err, commands.ErrUserNotInvited) {
		t.Fatalf("active: %v", err)
	}
	if e.users.Rows["active"].PasswordHash != "fake$right password 1" {
		t.Fatal("the active user must keep the hash")
	}
	link, err := cmd.Execute(ctx, commands.CreateInvite{UserID: "invited"})
	if err != nil || link.URL == "" {
		t.Fatalf("invited: %v", err)
	}
	if _, err := cmd.Execute(ctx, commands.CreateInvite{UserID: "missing"}); !errors.Is(err, commands.ErrUserNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestAcceptInvitePolicyErrorKeepsToken(t *testing.T) {
	e := newEnv()
	user, err := commands.NewCreateUser(e.invites()).Execute(ctx, commands.CreateUser{Email: "New@Example.com", Name: "New"})
	if err != nil {
		t.Fatal(err)
	}
	if user.User.Email != "new@example.com" {
		t.Fatalf("email = %q", user.User.Email)
	}
	if _, err := commands.NewCreateUser(e.invites()).Execute(ctx, commands.CreateUser{Email: "new@example.com", Name: "Again"}); !errors.Is(err, commands.ErrEmailTaken) {
		t.Fatalf("duplicate email: %v", err)
	}
	token := tokenOf(user.Invite.URL)
	accept := commands.NewAcceptInvite(e.invites())
	if _, err := accept.Execute(ctx, commands.AcceptInvite{Token: token, Password: "short"}); !errors.Is(err, domain.ErrPasswordTooShort) {
		t.Fatalf("short password: %v", err)
	}
	if ok, _ := e.tokens.IsValid(ctx, domain.HashSecret(token), domain.PurposeInvite, e.now); !ok {
		t.Fatal("a policy error must not use the token")
	}
	if _, err := accept.Execute(ctx, commands.AcceptInvite{Token: token, Password: "a good password 12"}); err != nil {
		t.Fatal(err)
	}
	if _, err := accept.Execute(ctx, commands.AcceptInvite{Token: token, Password: "a good password 12"}); !errors.Is(err, commands.ErrTokenInvalid) {
		t.Fatalf("second use: %v", err)
	}
}

// U6e: a token that is not valid gives ErrTokenInvalid before any hash runs.
func TestU6e_BadTokenRunsNoHash(t *testing.T) {
	e := newEnv()
	good := "a good password 12"
	setup := commands.NewCompleteSetup(e.setup())
	if _, err := setup.Execute(ctx, commands.CompleteSetup{Token: "nope", Email: "a@example.com", Name: "A", Password: good}); !errors.Is(err, commands.ErrTokenInvalid) {
		t.Fatalf("setup with a bad token: %v", err)
	}
	// A bad token is reported before the policy error of the password.
	if _, err := setup.Execute(ctx, commands.CompleteSetup{Token: "nope", Email: "a@example.com", Name: "A", Password: "short"}); !errors.Is(err, commands.ErrTokenInvalid) {
		t.Fatalf("setup with a bad token and a short password: %v", err)
	}
	accept := commands.NewAcceptInvite(e.invites())
	if _, err := accept.Execute(ctx, commands.AcceptInvite{Token: "nope", Password: good}); !errors.Is(err, commands.ErrTokenInvalid) {
		t.Fatalf("invite with a bad token: %v", err)
	}
	if _, err := accept.Execute(ctx, commands.AcceptInvite{Token: "", Password: good}); !errors.Is(err, commands.ErrTokenInvalid) {
		t.Fatalf("invite with an empty token: %v", err)
	}
	if e.hasher.Runs() != 0 {
		t.Fatalf("the hasher ran %d times, want 0", e.hasher.Runs())
	}
}

// U6f: a valid setup token does not make a second admin.
func TestU6f_SetupWithAdminFails(t *testing.T) {
	e := newEnv()
	res, err := commands.NewEnsureSetupToken(e.setup()).Execute(ctx, commands.EnsureSetupToken{})
	if err != nil || res.Link.URL == "" {
		t.Fatalf("ensure: %v", err)
	}
	e.addUser("admin", "admin@example.com", domain.UserActive, "x")
	_, _ = e.roles.Assign(ctx, "admin", domain.AdminRole, domain.AssignmentAPI)
	_, err = commands.NewCompleteSetup(e.setup()).Execute(ctx, commands.CompleteSetup{
		Token: tokenOf(res.Link.URL), Email: "second@example.com", Name: "Second", Password: "a good password 12",
	})
	if !errors.Is(err, commands.ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
	if len(e.users.Rows) != 1 {
		t.Fatalf("users = %d, want 1", len(e.users.Rows))
	}
}

func tokenOf(link string) string {
	const marker = "token="
	for i := 0; i+len(marker) <= len(link); i++ {
		if link[i:i+len(marker)] == marker {
			return link[i+len(marker):]
		}
	}
	return ""
}
