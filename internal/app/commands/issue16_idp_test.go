package commands_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
	"github.com/techorionai/constellation-identity/internal/ports/upstreamidp"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// idpEnv is the env of the upstream flows with a fake provider client.
type idpEnv struct {
	*linkEnv
	client *mock.IdpClient
	flows  *mock.IdpFlows
	idp    *commands.Idp
}

func newIdpEnv(t *testing.T) *idpEnv {
	t.Helper()
	e := &idpEnv{
		linkEnv: newLinkEnv(t),
		client:  &mock.IdpClient{On: map[string]bool{"google": true, "microsoft": true}, AuthURL: "https://provider.example.com/authorize"},
		flows:   mock.NewIdpFlows(),
	}
	idp, err := commands.NewIdp(commands.IdpDeps{
		Client: e.client, Flows: e.flows, Links: e.links, Users: e.users, Sessions: e.sessions, Tokens: e.env.tokens,
		MFA: e.mfa, UserRoles: e.roles, Pending: e.pending, Events: e.events, Tx: mock.Tx{}, Policy: policy,
		LookupAuthRequest: func(_ context.Context, id string) (commands.AuthRequestInfo, error) {
			if id == "gone" {
				return commands.AuthRequestInfo{}, commands.ErrAuthRequestGone
			}
			return commands.AuthRequestInfo{}, nil
		},
		PasskeysOn: true, RequireMFAForAdmins: true, Timeout: time.Second, Now: e.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.idp = idp
	return e
}

// start starts a flow and returns the state and the binding of the browser.
func (e *idpEnv) start(t *testing.T, in commands.StartIdp) (state, binding string) {
	t.Helper()
	got, err := e.idp.Start(ctx, in)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if got.Location != e.client.AuthURL || got.Binding == "" {
		t.Fatalf("started = %+v", got)
	}
	return e.client.Last.State, got.Binding
}

func (e *idpEnv) callback(state, binding string, in commands.CallbackIdp) (commands.IdpResult, error) {
	in.Provider, in.State, in.Binding = firstNonEmpty(in.Provider, "google"), state, binding
	return e.idp.Callback(ctx, in)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func loginStart() commands.StartIdp {
	return commands.StartIdp{Provider: "google", Purpose: domain.FlowLogin}
}

// U24: the checks of the start. A wrong place gives an error and no flow record.
func TestIssue16_U24_StartChecks(t *testing.T) {
	e := newIdpEnv(t)
	for name, in := range map[string]commands.StartIdp{
		"return_to of another host": {Provider: "google", Purpose: domain.FlowLogin, ReturnTo: "https://evil.example.com/"},
		"return_to with a scheme":   {Provider: "google", Purpose: domain.FlowLogin, ReturnTo: "//evil.example.com/x"},
		"auth request is gone":      {Provider: "google", Purpose: domain.FlowLogin, AuthRequest: "gone"},
		"unknown purpose":           {Provider: "google", Purpose: "other"},
		"link, cross-site":          {Provider: "google", Purpose: domain.FlowLink, SecFetchSite: "cross-site"},
		"invite, cross-site":        {Provider: "google", Purpose: domain.FlowInvite, SecFetchSite: "cross-site", InviteToken: "x"},
		"invite, same-site":         {Provider: "google", Purpose: domain.FlowInvite, SecFetchSite: "same-site", InviteToken: "x"},
		"invite, no valid token":    {Provider: "google", Purpose: domain.FlowInvite, InviteToken: "unknown"},
	} {
		if _, err := e.idp.Start(ctx, in); !errors.Is(err, commands.ErrIdpFailed) {
			t.Errorf("%s: err = %v, want ErrIdpFailed", name, err)
		}
	}
	if len(e.flows.Rows) != 0 {
		t.Fatalf("a wrong request made %d flow records", len(e.flows.Rows))
	}
	for _, p := range []string{"okta", "Google", ""} {
		if _, err := e.idp.Start(ctx, commands.StartIdp{Provider: p, Purpose: domain.FlowLogin}); !errors.Is(err, commands.ErrIdpProviderOff) {
			t.Errorf("provider %q: %v", p, err)
		}
	}
	e.client.On["google"] = false
	if _, err := e.idp.Start(ctx, loginStart()); !errors.Is(err, commands.ErrIdpProviderOff) {
		t.Errorf("provider off: %v", err)
	}
	e.client.On["google"] = true
	// A good start: the place is kept in the record, the record has the hash of
	// the state, and the secrets are random.
	state, binding := e.start(t, commands.StartIdp{Provider: "google", Purpose: domain.FlowLogin, ReturnTo: "/account/security?a=1", Fresh: true})
	rec := e.flows.Rows[domain.HashSecret(state)]
	if rec.ReturnTo != "/account/security?a=1" || !rec.Fresh || rec.BindingHash != domain.HashSecret(binding) || rec.Nonce == "" || rec.Verifier == "" {
		t.Fatalf("record = %+v", rec)
	}
	if !e.client.Last.Fresh || e.client.Last.Nonce != rec.Nonce || e.client.Last.Verifier != rec.Verifier {
		t.Fatalf("auth params = %+v", e.client.Last)
	}
	// A failure of the provider at the start makes no record.
	before := len(e.flows.Rows)
	e.client.AuthErr = upstreamidp.ErrProvider
	if _, err := e.idp.Start(ctx, loginStart()); !errors.Is(err, commands.ErrIdpProviderDown) {
		t.Errorf("provider down: %v", err)
	}
	if len(e.flows.Rows) != before {
		t.Fatal("a failed start must make no record")
	}
}

// I8: the state is used once, and it is bound to the browser.
func TestIssue16_StateAndBinding(t *testing.T) {
	e := newIdpEnv(t)
	e.addLink(linkID1, userA, "google")
	e.client.Identity = domain.UpstreamIdentity{Subject: "subject-" + linkID1, Email: "x@example.com"}
	state, binding := e.start(t, loginStart())
	if _, err := e.callback(state, "another-browser", commands.CallbackIdp{}); !errors.Is(err, commands.ErrIdpExpired) {
		t.Fatalf("binding of another browser: %v", err)
	}
	// The record is used by the first call, also when the call fails.
	if _, err := e.callback(state, binding, commands.CallbackIdp{}); !errors.Is(err, commands.ErrIdpExpired) {
		t.Fatalf("used state: %v", err)
	}
	if _, err := e.callback("unknown", binding, commands.CallbackIdp{}); !errors.Is(err, commands.ErrIdpExpired) {
		t.Fatalf("unknown state: %v", err)
	}
	if _, err := e.callback("", binding, commands.CallbackIdp{}); !errors.Is(err, commands.ErrIdpExpired) {
		t.Fatalf("empty state: %v", err)
	}
	state, _ = e.start(t, loginStart())
	if _, err := e.callback(state, "", commands.CallbackIdp{}); !errors.Is(err, commands.ErrIdpExpired) {
		t.Fatalf("no binding: %v", err)
	}
	// A record of another provider.
	state, binding = e.start(t, loginStart())
	if _, err := e.callback(state, binding, commands.CallbackIdp{Provider: "microsoft"}); !errors.Is(err, commands.ErrIdpExpired) {
		t.Fatalf("provider of another record: %v", err)
	}
	if len(e.sessions.Rows) != 0 {
		t.Fatal("no session")
	}
}

// I5, I7: a linked user logs in with the session fed. An account that is not
// linked gets no session, also when its email is the email of a user.
func TestIssue16_LoginWithLink(t *testing.T) {
	e := newIdpEnv(t)
	e.addLink(linkID1, userA, "google")
	e.client.Identity = domain.UpstreamIdentity{Subject: "subject-" + linkID1, Email: "a@example.com"}
	state, binding := e.start(t, commands.StartIdp{Provider: "google", Purpose: domain.FlowLogin, AuthRequest: "ar-1", ReturnTo: "/x"})
	res, err := e.callback(state, binding, commands.CallbackIdp{IP: "1.1.1.1", UserAgent: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != commands.IdpSession || res.Session.UserID != userA || strings.Join(res.Session.AuthMethods, " ") != "fed" ||
		res.AuthRequest != "ar-1" || res.ReturnTo != "/x" || res.Session.Token == "" {
		t.Fatalf("result = %+v", res)
	}
	if got := e.links.Rows[linkID1]; got.LastUsedAt == nil || got.Email != "a@example.com" {
		t.Fatalf("link = %+v", got)
	}

	// I7: the email of a user, and no link.
	e.client.Identity = domain.UpstreamIdentity{Subject: "unlinked", Email: "b@example.com", EmailVerified: true}
	before := len(e.sessions.Rows)
	state, binding = e.start(t, loginStart())
	if _, err := e.callback(state, binding, commands.CallbackIdp{}); !errors.Is(err, commands.ErrIdpNotLinked) {
		t.Fatalf("not linked: %v", err)
	}
	if len(e.sessions.Rows) != before || len(e.links.Rows) != 1 {
		t.Fatal("no session and no link")
	}

	// A disabled user does not log in.
	e.users.Rows[userA] = func() domain.User { u := e.users.Rows[userA]; u.Status = domain.UserDisabled; return u }()
	e.client.Identity = domain.UpstreamIdentity{Subject: "subject-" + linkID1}
	state, binding = e.start(t, loginStart())
	if _, err := e.callback(state, binding, commands.CallbackIdp{}); !errors.Is(err, commands.ErrIdpFailed) {
		t.Fatalf("disabled user: %v", err)
	}
}

// I6: a user with a local second factor gets a pending login with the first
// factor fed. The service does not trust the second factor of the provider.
func TestIssue16_LoginWithSecondFactor(t *testing.T) {
	e := newIdpEnv(t)
	e.enable(t, userA, "a@example.com")
	e.addLink(linkID1, userA, "google")
	e.client.Identity = domain.UpstreamIdentity{Subject: "subject-" + linkID1}
	state, binding := e.start(t, commands.StartIdp{Provider: "google", Purpose: domain.FlowLogin, AuthRequest: "ar-1"})
	sessionsBefore := len(e.sessions.Rows)
	res, err := e.callback(state, binding, commands.CallbackIdp{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != commands.IdpPending || res.Session.PendingToken == "" || res.Session.Token != "" {
		t.Fatalf("result = %+v", res)
	}
	p, err := e.pending.Get(ctx, domain.HashSecret(res.Session.PendingToken))
	if err != nil || strings.Join(p.Methods, " ") != "fed" || p.UserID != userA || p.AuthRequest != "ar-1" {
		t.Fatalf("pending = %+v, %v", p, err)
	}
	if len(e.sessions.Rows) != sessionsBefore {
		t.Fatal("no session before the second factor")
	}
	// An admin with no second factor gets a session and must set up MFA.
	e.addLink(linkID2, adminID, "google")
	e.client.Identity = domain.UpstreamIdentity{Subject: "subject-" + linkID2}
	state, binding = e.start(t, loginStart())
	res, err = e.callback(state, binding, commands.CallbackIdp{})
	if err != nil || res.Kind != commands.IdpSession || !res.Session.SetupRequired {
		t.Fatalf("admin: %+v, %v", res, err)
	}
}

// I9, I20, I23, I37 and the outcomes: each failure of the provider or of the
// token gives one error and no session.
func TestIssue16_CallbackFailures(t *testing.T) {
	e := newIdpEnv(t)
	e.addLink(linkID1, userA, "google")
	e.client.Identity = domain.UpstreamIdentity{Subject: "subject-" + linkID1}
	run := func(in commands.CallbackIdp) error {
		state, binding := e.start(t, loginStart())
		_, err := e.callback(state, binding, in)
		return err
	}
	if err := run(commands.CallbackIdp{ProviderError: true}); !errors.Is(err, commands.ErrIdpFailed) {
		t.Errorf("error parameter: %v", err)
	}
	e.client.ExchangeErr = upstreamidp.ErrToken
	if err := run(commands.CallbackIdp{}); !errors.Is(err, commands.ErrIdpFailed) {
		t.Errorf("bad token: %v", err)
	}
	e.client.ExchangeErr = upstreamidp.ErrProvider
	if err := run(commands.CallbackIdp{}); !errors.Is(err, commands.ErrIdpFailed) {
		t.Errorf("provider error: %v", err)
	}
	if len(e.sessions.Rows) != 0 {
		t.Fatal("no session")
	}
}

// I34: a flow that needs a fresh login refuses an old upstream login.
func TestIssue16_FreshRule(t *testing.T) {
	e := newIdpEnv(t)
	e.addLink(linkID1, userA, "microsoft")
	old := e.now.Add(-10 * time.Minute)
	e.client.Identity = domain.UpstreamIdentity{Subject: "subject-" + linkID1, AuthTime: old, IssuedAt: old}
	in := commands.StartIdp{Provider: "microsoft", Purpose: domain.FlowLogin, Fresh: true}
	state, binding := e.start(t, in)
	if _, err := e.callback(state, binding, commands.CallbackIdp{Provider: "microsoft"}); !errors.Is(err, commands.ErrIdpFailed) {
		t.Fatalf("old login: %v", err)
	}
	e.client.Identity.AuthTime, e.client.Identity.IssuedAt = e.now, e.now
	state, binding = e.start(t, in)
	if _, err := e.callback(state, binding, commands.CallbackIdp{Provider: "microsoft"}); err != nil {
		t.Fatalf("fresh login: %v", err)
	}
	// No fresh flag: an old login is fine.
	e.client.Identity.AuthTime, e.client.Identity.IssuedAt = old, old
	state, binding = e.start(t, commands.StartIdp{Provider: "microsoft", Purpose: domain.FlowLogin})
	if _, err := e.callback(state, binding, commands.CallbackIdp{Provider: "microsoft"}); err != nil {
		t.Fatalf("no fresh flag: %v", err)
	}
}

// I4, I10: the link flow. It needs a fresh session. It adds the link, the audit
// entry, and the notice. It refuses an account of another user and a second
// link of the provider.
func TestIssue16_LinkFlow(t *testing.T) {
	e := newIdpEnv(t)
	sessionToken := "session-token-1"
	e.sessions.Rows["s1"] = domain.Session{
		ID: "s1", UserID: userA, TokenHash: domain.HashSecret(sessionToken), AuthTime: e.now,
		ExpiresAt: e.now.Add(time.Hour), IdleExpiresAt: e.now.Add(time.Hour),
	}
	link := commands.StartIdp{Provider: "google", Purpose: domain.FlowLink, SessionToken: sessionToken, SecFetchSite: "same-origin"}
	// A session that is too old needs a new login.
	old := e.sessions.Rows["s1"]
	old.AuthTime = e.now.Add(-6 * time.Minute)
	e.sessions.Rows["s1"] = old
	if _, err := e.idp.Start(ctx, link); !errors.Is(err, commands.ErrIdpReauth) {
		t.Fatalf("old session: %v", err)
	}
	old.AuthTime = e.now
	e.sessions.Rows["s1"] = old
	if _, err := e.idp.Start(ctx, commands.StartIdp{Provider: "google", Purpose: domain.FlowLink}); !errors.Is(err, commands.ErrIdpReauth) {
		t.Fatalf("no session: %v", err)
	}
	state, binding := e.start(t, link)
	if !e.client.Last.Fresh {
		t.Fatal("the link flow needs a fresh login at the provider")
	}
	e.client.Identity = domain.UpstreamIdentity{Provider: "google", Subject: "new-subject", Email: "up@example.com", AuthTime: e.now, IssuedAt: e.now}
	// The session of the callback must be the session of the start.
	if _, err := e.callback(state, binding, commands.CallbackIdp{SessionToken: "other-session"}); !errors.Is(err, commands.ErrIdpReauth) {
		t.Fatalf("another session: %v", err)
	}
	state, binding = e.start(t, link)
	res, err := e.callback(state, binding, commands.CallbackIdp{SessionToken: sessionToken})
	if err != nil || res.Kind != commands.IdpLinked {
		t.Fatalf("link: %+v, %v", res, err)
	}
	got, err := e.links.GetByUserProvider(ctx, userA, "google")
	if err != nil || got.Subject != "new-subject" || got.Email != "up@example.com" {
		t.Fatalf("link = %+v, %v", got, err)
	}
	if len(e.events.Audits) != 1 || e.events.Audits[0].Action != securityevents.ActionIdentityLinkAdd ||
		e.events.Audits[0].TargetUserID != userA || e.events.Audits[0].Changes["provider"] != "google" {
		t.Fatalf("audits = %+v", e.events.Audits)
	}
	if len(e.events.Notices) != 1 || e.events.Notices[0].Kind != securityevents.NoticeIdentityLinkAdded {
		t.Fatalf("notices = %+v", e.events.Notices)
	}
	// A second link of the same provider.
	state, binding = e.start(t, link)
	if _, err := e.callback(state, binding, commands.CallbackIdp{SessionToken: sessionToken}); !errors.Is(err, commands.ErrIdpAlreadyLinked) {
		t.Fatalf("second link: %v", err)
	}
	// I10: an account that another user has.
	e.addLink(linkID2, userB, "microsoft")
	e.client.Identity = domain.UpstreamIdentity{Subject: "subject-" + linkID2, AuthTime: e.now, IssuedAt: e.now}
	state, binding = e.start(t, commands.StartIdp{Provider: "microsoft", Purpose: domain.FlowLink, SessionToken: sessionToken})
	if _, err := e.callback(state, binding, commands.CallbackIdp{Provider: "microsoft", SessionToken: sessionToken}); !errors.Is(err, commands.ErrIdpLinkedElsewhere) {
		t.Fatalf("account of another user: %v", err)
	}
	if n := len(e.links.Rows); n != 2 {
		t.Fatalf("links = %d", n)
	}
	if len(e.events.Audits) != 1 {
		t.Fatal("a refused link writes no audit entry")
	}
}

// I11, I12: the invite with an upstream account.
func TestIssue16_InviteFlow(t *testing.T) {
	e := newIdpEnv(t)
	e.addUser(userNoPassword, "invited@example.com", domain.UserInvited, "")
	e.env.tokens.Rows["h"] = domain.OneTimeToken{
		Hash: domain.HashSecret("invite-token"), Purpose: domain.PurposeInvite, UserID: userNoPassword, ExpiresAt: e.now.Add(time.Hour),
	}
	delete(e.env.tokens.Rows, "h")
	e.env.tokens.Rows[domain.HashSecret("invite-token")] = domain.OneTimeToken{
		Hash: domain.HashSecret("invite-token"), Purpose: domain.PurposeInvite, UserID: userNoPassword, ExpiresAt: e.now.Add(time.Hour),
	}
	in := commands.StartIdp{Provider: "google", Purpose: domain.FlowInvite, InviteToken: "invite-token", SecFetchSite: "same-origin"}
	cases := map[string]domain.UpstreamIdentity{
		"email not verified": {Subject: "s-1", Email: "invited@example.com", EmailVerified: false},
		"another email":      {Subject: "s-1", Email: "other@example.com", EmailVerified: true},
		"no email":           {Subject: "s-1", EmailVerified: true},
	}
	for name, id := range cases {
		e.client.Identity = id
		state, binding := e.start(t, in)
		if _, err := e.callback(state, binding, commands.CallbackIdp{}); !errors.Is(err, commands.ErrIdpMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(e.links.Rows) != 0 || e.users.Rows[userNoPassword].Status != domain.UserInvited {
		t.Fatal("a mismatch must change nothing")
	}
	// The token can still be used with a password.
	if ok, _ := e.env.tokens.IsValid(ctx, domain.HashSecret("invite-token"), domain.PurposeInvite, e.now); !ok {
		t.Fatal("the token must stay valid")
	}
	// The email is normalized.
	e.client.Identity = domain.UpstreamIdentity{Subject: "s-1", Email: " Invited@Example.com ", EmailVerified: true}
	state, binding := e.start(t, in)
	res, err := e.callback(state, binding, commands.CallbackIdp{IP: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != commands.IdpSession || strings.Join(res.Session.AuthMethods, " ") != "fed" || res.Purpose != domain.FlowInvite {
		t.Fatalf("result = %+v", res)
	}
	u := e.users.Rows[userNoPassword]
	if u.Status != domain.UserActive || u.PasswordHash != "" {
		t.Fatalf("user = %+v", u)
	}
	if _, err := e.links.GetBySubject(ctx, "google", "s-1"); err != nil {
		t.Fatalf("link: %v", err)
	}
	if ok, _ := e.env.tokens.IsValid(ctx, domain.HashSecret("invite-token"), domain.PurposeInvite, e.now); ok {
		t.Fatal("the token must be used")
	}
	if len(e.events.Audits) != 1 || e.events.Audits[0].Action != securityevents.ActionIdentityLinkAdd || len(e.events.Notices) != 1 {
		t.Fatalf("events = %+v %+v", e.events.Audits, e.events.Notices)
	}
	// The token is used: a second flow does not start.
	if _, err := e.idp.Start(ctx, in); !errors.Is(err, commands.ErrIdpFailed) {
		t.Fatalf("used token: %v", err)
	}
}
