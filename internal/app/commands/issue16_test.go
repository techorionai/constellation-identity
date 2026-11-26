package commands_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

const (
	userNoPassword = "00000000-0000-4000-8000-0000000000c1"
	linkID1        = "00000000-0000-4000-8000-0000000000d1"
	linkID2        = "00000000-0000-4000-8000-0000000000d2"
)

// linkEnv is the env of the use cases of the upstream links.
type linkEnv struct {
	*passkeyEnv
	links  *mock.IdentityLinks
	tokens *mock.APITokens
	logs   *bytes.Buffer
	// googleOn and microsoftOn are the providers that are on.
	on     map[string]bool
	links2 *commands.IdentityLinks
}

func newLinkEnv(t *testing.T) *linkEnv {
	t.Helper()
	p := newPasskeyEnv(t)
	e := &linkEnv{passkeyEnv: p, links: mock.NewIdentityLinks(), logs: &bytes.Buffer{}, on: map[string]bool{"google": true, "microsoft": true}}
	e.tokens = mock.NewAPITokens(p.users)
	e.addUser(userNoPassword, "nopw@example.com", domain.UserActive, "")
	e.rebuild(t, true)
	return e
}

func (e *linkEnv) providerOn(p string) bool { return e.on[p] }

// rebuild makes the use cases with the current settings.
func (e *linkEnv) rebuild(t *testing.T, passkeysOn bool) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(e.logs, nil))
	cmd, err := commands.NewMFA(commands.MFADeps{
		Users: e.users, UserRoles: e.roles, Sessions: e.sessions, MFA: e.mfa, TOTP: e.totp, Sealer: mock.Sealer{}, Hasher: e.hasher,
		Passkeys: e.keys, WebAuthn: e.wa, Ceremonies: e.ceremonies, PasskeysOn: passkeysOn,
		Links: e.links, APITokens: e.tokens, ProviderOn: e.providerOn,
		Pending: e.pending, Setups: e.setups, Failures: e.failures, Limiter: e.limiter, Events: e.events, Tx: mock.Tx{},
		Policy: policy, RequireMFAForAdmins: e.require, Issuer: "Constellation", MaxFailures: 10, FailureWindow: 15 * time.Minute,
		Log: log, Now: e.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.cmd = cmd
	e.links2 = commands.NewIdentityLinks(commands.IdentityLinksDeps{
		Users: e.users, Links: e.links, Sessions: e.sessions, APITokens: e.tokens, MFA: e.mfa, Events: e.events, Tx: mock.Tx{},
		PasskeysOn: passkeysOn, ProviderOn: e.providerOn, Log: log, Now: e.clock,
	})
}

func (e *linkEnv) addLink(id, userID, provider string) {
	e.links.Rows[id] = domain.IdentityLink{
		ID: id, UserID: userID, Provider: provider, Subject: "subject-" + id, Email: "secret-" + id + "@upstream.example.com", CreatedAt: e.now,
	}
}

// addSession adds a session with methods and returns its ID.
func (e *linkEnv) addSession(id, userID string, methods ...string) {
	e.sessions.Rows[id] = domain.Session{ID: id, UserID: userID, AuthMethods: methods, AuthTime: e.now, ExpiresAt: e.now.Add(time.Hour), IdleExpiresAt: e.now.Add(time.Hour)}
}

// addToken adds an API token that a session with the methods made.
func (e *linkEnv) addToken(hash, userID string, methods ...string) {
	e.tokens.Rows[hash] = domain.APIToken{ID: "tok-" + hash, UserID: userID, AMR: methods, ExpiresAt: e.now.Add(time.Hour)}
}

func (e *linkEnv) revoked(id string) bool        { return e.sessions.Rows[id].RevokedAt != nil }
func (e *linkEnv) tokenRevoked(hash string) bool { return e.tokens.Rows[hash].RevokedAt != nil }

// U7: the last login method. A user with no password and no passkey cannot
// remove the only link. The refusal revokes nothing.
func TestIssue16_U7_LastLinkRefused(t *testing.T) {
	e := newLinkEnv(t)
	e.addLink(linkID1, userNoPassword, "google")
	e.addSession("fed-session", userNoPassword, "fed")
	e.addToken("fed-token", userNoPassword, "fed")
	err := e.links2.Remove(ctx, commands.RemoveIdentityLink{UserID: userNoPassword, Provider: "google", Actor: userNoPassword})
	if !errors.Is(err, commands.ErrLastLoginMethod) {
		t.Fatalf("err = %v, want last_login_method", err)
	}
	if len(e.links.Rows) != 1 || e.revoked("fed-session") || e.tokenRevoked("fed-token") {
		t.Fatal("a refused removal must change nothing")
	}
	if len(e.events.Audits) != 0 || len(e.events.Notices) != 0 {
		t.Fatal("a refused removal writes no audit entry")
	}
	// A second link of a provider that is on lets the user remove the first.
	e.addLink(linkID2, userNoPassword, "microsoft")
	if err := e.links2.Remove(ctx, commands.RemoveIdentityLink{UserID: userNoPassword, Provider: "google", Actor: userNoPassword}); err != nil {
		t.Fatalf("remove with a second link: %v", err)
	}
	// A link of a provider that is off does not count.
	e.addLink(linkID1, userNoPassword, "google")
	e.on["microsoft"] = false
	err = e.links2.Remove(ctx, commands.RemoveIdentityLink{UserID: userNoPassword, Provider: "google", Actor: userNoPassword})
	if !errors.Is(err, commands.ErrLastLoginMethod) {
		t.Fatalf("with the other provider off: %v", err)
	}
}

// U27: a link removal revokes the sessions and the API tokens that a fed session
// made, and writes the audit entry and the notice with no subject and no email.
func TestIssue16_U27_LinkRemovalRevokes(t *testing.T) {
	e := newLinkEnv(t)
	e.addLink(linkID1, userA, "google")
	e.addSession("fed", userA, "fed")
	e.addSession("fed-mfa", userA, "fed", "otp", "mfa")
	e.addSession("pwd", userA, "pwd")
	e.addSession("other-user", userB, "fed")
	e.addToken("t-fed", userA, "fed")
	e.addToken("t-pwd", userA, "pwd", "otp", "mfa")
	e.addToken("t-empty", userA)
	e.addToken("t-other", userB, "fed")
	if err := e.links2.Remove(ctx, commands.RemoveIdentityLink{UserID: userA, Provider: "google", Actor: userA}); err != nil {
		t.Fatal(err)
	}
	if !e.revoked("fed") || !e.revoked("fed-mfa") || e.revoked("pwd") || e.revoked("other-user") {
		t.Fatal("only the fed sessions of the user end")
	}
	if !e.tokenRevoked("t-fed") || e.tokenRevoked("t-pwd") || e.tokenRevoked("t-empty") || e.tokenRevoked("t-other") {
		t.Fatal("only the tokens that a fed session made end")
	}
	if len(e.links.Rows) != 0 {
		t.Fatal("the link must be gone")
	}
	if len(e.events.Audits) != 1 || e.events.Audits[0].Action != securityevents.ActionIdentityLinkRemove ||
		e.events.Audits[0].TargetUserID != userA || e.events.Audits[0].Changes["provider"] != "google" || e.events.Audits[0].Result != securityevents.ResultSuccess {
		t.Fatalf("audits = %+v", e.events.Audits)
	}
	if len(e.events.Notices) != 1 || e.events.Notices[0].Kind != securityevents.NoticeIdentityLinkRemoved {
		t.Fatalf("notices = %+v", e.events.Notices)
	}
	for _, v := range e.events.Audits[0].Changes {
		if strings.Contains(v, "subject") || strings.Contains(v, "@") {
			t.Fatalf("the audit entry has a subject or an email: %v", e.events.Audits[0].Changes)
		}
	}
}

// I31 at the commands: the order of the checks and the 404 rules.
func TestIssue16_LinkRemovalErrors(t *testing.T) {
	e := newLinkEnv(t)
	e.addLink(linkID1, userA, "google")
	remove := func(user, provider string, check bool) error {
		return e.links2.Remove(ctx, commands.RemoveIdentityLink{UserID: user, Provider: provider, Actor: user, CheckUser: check})
	}
	for _, p := range []string{"okta", "Google", "", "microsoft"} {
		if err := remove(userA, p, false); !errors.Is(err, commands.ErrIdentityLinkNotFound) {
			t.Errorf("provider %q: %v", p, err)
		}
	}
	if err := remove("not-a-uuid", "google", true); !errors.Is(err, commands.ErrUserNotFound) {
		t.Errorf("bad user ID: %v", err)
	}
	if err := remove("00000000-0000-4000-8000-0000000000ff", "okta", true); !errors.Is(err, commands.ErrUserNotFound) {
		t.Errorf("unknown user with a wrong provider: %v", err)
	}
}

// The list of the links: the order, the paging, and the user check.
func TestIssue16_LinkList(t *testing.T) {
	e := newLinkEnv(t)
	e.addLink(linkID1, userA, "microsoft")
	e.addLink(linkID2, userA, "google")
	page, err := e.links2.List(ctx, userA, commands.ListPage{}, true)
	if err != nil || len(page.Items) != 2 || page.Items[0].Provider != "google" || page.Items[1].Provider != "microsoft" || page.Next != "" {
		t.Fatalf("page = %+v, %v", page, err)
	}
	one := int32(1)
	page, err = e.links2.List(ctx, userA, commands.ListPage{Size: &one}, true)
	if err != nil || len(page.Items) != 1 || page.Next == "" {
		t.Fatalf("page 1 = %+v, %v", page, err)
	}
	page2, err := e.links2.List(ctx, userA, commands.ListPage{Size: &one, Token: page.Next}, true)
	if err != nil || len(page2.Items) != 1 || page2.Items[0].Provider != "microsoft" || page2.Next != "" {
		t.Fatalf("page 2 = %+v, %v", page2, err)
	}
	if _, err := e.links2.List(ctx, "00000000-0000-4000-8000-0000000000ff", commands.ListPage{}, true); !errors.Is(err, commands.ErrUserNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

// U27 for the passkeys: a removal revokes the API tokens that a session with a
// passkey made. The rule "last login method" refuses a removal that leaves no
// method, and then it revokes nothing.
func TestIssue16_U27_PasskeyRemoval(t *testing.T) {
	e := newLinkEnv(t)
	e.addPasskey(userA, passkeyID1, "key")
	e.addSession("hwk", userA, "hwk", "user", "mfa")
	e.addSession("pwd", userA, "pwd")
	e.addToken("t-hwk", userA, "hwk", "user", "mfa")
	e.addToken("t-pwd", userA, "pwd")
	if err := e.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: userA, PasskeyID: passkeyID1, Actor: userA}); err != nil {
		t.Fatal(err)
	}
	if !e.revoked("hwk") || e.revoked("pwd") || !e.tokenRevoked("t-hwk") || e.tokenRevoked("t-pwd") {
		t.Fatal("only the hwk sessions and tokens end")
	}

	// No password and no link: the only passkey is the last login method.
	e.addPasskey(userNoPassword, passkeyID2, "only")
	e.addSession("hwk2", userNoPassword, "hwk", "mfa")
	e.addToken("t-hwk2", userNoPassword, "hwk")
	err := e.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: userNoPassword, PasskeyID: passkeyID2, Actor: userNoPassword})
	if !errors.Is(err, commands.ErrLastLoginMethod) {
		t.Fatalf("err = %v, want last_login_method", err)
	}
	if n, _ := e.keys.Count(ctx, userNoPassword); n != 1 || e.revoked("hwk2") || e.tokenRevoked("t-hwk2") {
		t.Fatal("a refused removal must change nothing")
	}
	// A link of a provider that is on is a login method, so the removal works.
	e.addLink(linkID1, userNoPassword, "google")
	if err := e.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: userNoPassword, PasskeyID: passkeyID2, Actor: userNoPassword}); err != nil {
		t.Fatalf("remove with a link: %v", err)
	}
}

// I29: mfa_required comes before last_login_method.
func TestIssue16_MFARequiredFirst(t *testing.T) {
	e := newLinkEnv(t)
	// An admin with no password and only a passkey: the policy needs MFA, and the
	// passkey is the last second factor and the last login method.
	u := e.users.Rows[adminID]
	u.PasswordHash = ""
	e.users.Rows[adminID] = u
	e.addPasskey(adminID, passkeyID1, "key")
	err := e.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: adminID, PasskeyID: passkeyID1, Actor: adminID})
	if !errors.Is(err, commands.ErrMFARequired) {
		t.Fatalf("err = %v, want mfa_required", err)
	}
}

// I29, I30: the reset of the MFA removes all passkeys. It refuses a user that has
// no login method after the reset. The subcommand skips the rule, logs the
// event, and does not change the status.
func TestIssue16_ResetLastLoginMethod(t *testing.T) {
	e := newLinkEnv(t)
	e.addPasskey(userNoPassword, passkeyID1, "only")
	e.addSession("hwk", userNoPassword, "hwk", "mfa")
	e.addToken("t-hwk", userNoPassword, "hwk")
	err := e.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: userNoPassword, Actor: adminID})
	if !errors.Is(err, commands.ErrLastLoginMethod) {
		t.Fatalf("err = %v, want last_login_method", err)
	}
	if n, _ := e.keys.Count(ctx, userNoPassword); n != 1 || e.revoked("hwk") || e.users.Rows[userNoPassword].Status != domain.UserActive {
		t.Fatal("a refused reset must change nothing")
	}
	// The actor is the user: mfa_required comes first.
	if err := e.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: userNoPassword, Actor: userNoPassword}); !errors.Is(err, commands.ErrMFARequired) {
		t.Fatalf("own reset: %v", err)
	}
	// The subcommand.
	if err := e.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: userNoPassword, Actor: securityevents.ActorCLI, Operator: true}); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.keys.Count(ctx, userNoPassword); n != 0 || !e.revoked("hwk") || !e.tokenRevoked("t-hwk") {
		t.Fatal("the reset must remove the passkeys and revoke the hwk sessions and tokens")
	}
	if e.users.Rows[userNoPassword].Status != domain.UserActive {
		t.Fatal("the reset does not change the status")
	}
	if !strings.Contains(e.logs.String(), "identity.mfa.reset_last_login_method") {
		t.Fatalf("log = %s", e.logs.String())
	}
	// A user with a password: no event.
	e.logs.Reset()
	e.addPasskey(userA, passkeyID2, "key")
	if err := e.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: userA, Actor: securityevents.ActorCLI, Operator: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(e.logs.String(), "reset_last_login_method") {
		t.Fatal("a user with a password needs no event")
	}
}

// U14: the second factor after an upstream login keeps the first factor fed. The
// TOTP setup in a fed session keeps it too.
func TestIssue16_U14_SecondFactorKeepsFed(t *testing.T) {
	le := newLinkEnv(t)
	m := le.mfaEnv
	le.addLink(linkID1, userA, "google")
	secret, codes := m.enable(t, userA, "a@example.com")
	put := func(token string) {
		err := m.pending.Put(ctx, domain.HashSecret(token), domain.PendingLogin{
			UserID: userA, Methods: domain.MethodsFederated(), Provider: "google", ExpiresAt: m.now.Add(time.Minute),
		}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}
	put("pending-1")
	got, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: "pending-1", Code: m.code(secret, m.now), IP: "1.1.1.1"})
	if err != nil || strings.Join(got.Session.AuthMethods, " ") != "fed otp mfa" {
		t.Fatalf("totp: %+v, %v", got.Session.AuthMethods, err)
	}
	put("pending-2")
	got, err = m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: "pending-2", Code: codes[0], Recovery: true, IP: "1.1.1.1"})
	if err != nil || strings.Join(got.Session.AuthMethods, " ") != "fed rec mfa" {
		t.Fatalf("recovery: %+v, %v", got.Session.AuthMethods, err)
	}
	// The page of the second factor knows that the first factor was upstream.
	put("pending-3")
	info, err := m.cmd.CheckPending(ctx, "pending-3")
	if err != nil || !info.Federated {
		t.Fatalf("info = %+v, %v", info, err)
	}

	// The TOTP setup of a user in a fed session.
	m2 := newMFAEnv(t)
	m2.sessions.Rows["s1"] = domain.Session{ID: "s1", UserID: userB, AuthMethods: []string{"fed"}}
	info2, err := m2.cmd.BeginSetup(ctx, commands.BeginSetup{SessionID: "s1", UserID: userB, Account: "b@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m2.setups.Get(ctx, domain.HashSecret("s1"))
	if err != nil || info2.Secret == "" {
		t.Fatal(err)
	}
	sec, err := mock.Sealer{}.Open("setup:"+userB, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m2.cmd.FinishSetup(ctx, commands.FinishSetup{SessionID: "s1", UserID: userB, Code: m2.code(sec, m2.now)}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m2.sessions.Rows["s1"].AuthMethods, " "); got != "fed otp mfa" {
		t.Fatalf("methods after the setup = %q", got)
	}
}

// P19, I40: the API token records the amr of the session that made it, and the
// removal of a login method revokes only the tokens of that method (U26).
func TestIssue16_APITokenRecordsAMR(t *testing.T) {
	e := newTokenEnv()
	cmd := e.cmd()
	fedTok, err := cmd.Create(ctx, commands.CreateAPIToken{UserID: user1, Name: "fed", Scope: "helpdesk:ticket:read", AMR: []string{"fed", "otp", "mfa"}})
	if err != nil {
		t.Fatal(err)
	}
	pwdTok, err := cmd.Create(ctx, commands.CreateAPIToken{UserID: user1, Name: "pwd", Scope: "helpdesk:ticket:read", AMR: []string{"pwd"}})
	if err != nil {
		t.Fatal(err)
	}
	oldTok, err := cmd.Create(ctx, commands.CreateAPIToken{UserID: user1, Name: "old", Scope: "helpdesk:ticket:read"})
	if err != nil {
		t.Fatal(err)
	}
	hwkTok, err := cmd.Create(ctx, commands.CreateAPIToken{UserID: user1, Name: "hwk", Scope: "helpdesk:ticket:read", AMR: []string{"hwk", "mfa"}})
	if err != nil {
		t.Fatal(err)
	}
	rows := func() map[string]domain.APIToken {
		out := map[string]domain.APIToken{}
		for _, r := range e.api.Rows {
			out[r.Name] = r
		}
		return out
	}
	if got := strings.Join(rows()["fed"].AMR, " "); got != "fed otp mfa" || len(rows()["old"].AMR) != 0 {
		t.Fatalf("amr = %q, old = %v", got, rows()["old"].AMR)
	}
	_, _ = fedTok, pwdTok
	_, _ = oldTok, hwkTok
	// U26: RevokeWithMethod revokes only the tokens with the method. A token that
	// is revoked already keeps its first revoked_at.
	first := e.now.Add(-time.Hour)
	for h, r := range e.api.Rows {
		if r.Name == "hwk" {
			r.RevokedAt = &first
			e.api.Rows[h] = r
		}
	}
	for _, method := range []string{"fed", "hwk"} {
		n, err := e.api.RevokeWithMethod(ctx, user1, method, e.now)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[string]int{"fed": 1, "hwk": 0}[method]; n != want {
			t.Fatalf("revoked with %s = %d, want %d", method, n, want)
		}
	}
	got := rows()
	if got["fed"].RevokedAt == nil || got["pwd"].RevokedAt != nil || got["old"].RevokedAt != nil || !got["hwk"].RevokedAt.Equal(first) {
		t.Fatalf("revoked_at: fed %v, pwd %v, old %v, hwk %v", got["fed"].RevokedAt, got["pwd"].RevokedAt, got["old"].RevokedAt, got["hwk"].RevokedAt)
	}
}

// U32 (R1, P22): the first password writes the audit entry and sends the notice.
// A user with a password gets an error and no entry.
func TestIssue16_U32_SetPasswordAudit(t *testing.T) {
	e := newLinkEnv(t)
	cmd := commands.NewSetPassword(commands.SetPasswordDeps{
		Users: e.users, Hasher: e.hasher, Tx: mock.Tx{}, Events: e.events, Now: e.clock,
	})
	if err := cmd.Execute(ctx, commands.SetPassword{UserID: userNoPassword, Password: "a long new password", Actor: userNoPassword}); err != nil {
		t.Fatal(err)
	}
	if e.users.Rows[userNoPassword].PasswordHash == "" {
		t.Fatal("the password must be set")
	}
	if len(e.events.Audits) != 1 || e.events.Audits[0].Action != "identity:password:set" ||
		e.events.Audits[0].Actor != userNoPassword || e.events.Audits[0].TargetUserID != userNoPassword ||
		e.events.Audits[0].Result != securityevents.ResultSuccess {
		t.Fatalf("audits = %+v", e.events.Audits)
	}
	if len(e.events.Notices) != 1 || e.events.Notices[0].Kind != "password_set" || e.events.Notices[0].TargetUserID != userNoPassword {
		t.Fatalf("notices = %+v", e.events.Notices)
	}
	if strings.Contains(e.logs.String(), "a long new password") {
		t.Fatal("the log must not have the password")
	}
	// The user has a password now. A second call changes nothing and writes no entry.
	err := cmd.Execute(ctx, commands.SetPassword{UserID: userNoPassword, Password: "another long password", Actor: userNoPassword})
	if !errors.Is(err, commands.ErrPasswordSet) || len(e.events.Audits) != 1 || len(e.events.Notices) != 1 {
		t.Fatalf("second call: %v, audits %d, notices %d", err, len(e.events.Audits), len(e.events.Notices))
	}
	// A password that breaks the rules writes no entry.
	e.events.Audits, e.events.Notices = nil, nil
	e.addUser(userB, "b2@example.com", domain.UserActive, "")
	if err := cmd.Execute(ctx, commands.SetPassword{UserID: userB, Password: "short", Actor: userB}); err == nil {
		t.Fatal("a short password must fail")
	}
	if len(e.events.Audits) != 0 || len(e.events.Notices) != 0 {
		t.Fatal("a failed call writes no entry")
	}
}

// U33 (R3, P23): the own removal of a link needs a local factor and its proof.
// A user with no local factor cannot remove a link. The admin removal needs no
// proof of the user.
func TestIssue16_U33_RemovalNeedsLocalFactor(t *testing.T) {
	e := newLinkEnv(t)
	e.addLink(linkID1, userA, "google")
	e.addLink(linkID2, userA, "microsoft")
	rm := func(self, verified bool) error {
		return e.links2.Remove(ctx, commands.RemoveIdentityLink{UserID: userA, Provider: "google", Actor: userA, Self: self, FactorVerified: verified})
	}
	// The user has a password, but the caller gave no proof.
	if err := rm(true, false); !errors.Is(err, commands.ErrLocalFactorRequired) {
		t.Fatalf("no proof: %v", err)
	}
	if len(e.links.Rows) != 2 {
		t.Fatal("a refusal changes nothing")
	}
	// A user with two links, no password, and no TOTP has no local factor.
	e.addLink("00000000-0000-4000-8000-0000000000d3", userNoPassword, "google")
	e.addLink("00000000-0000-4000-8000-0000000000d4", userNoPassword, "microsoft")
	err := e.links2.Remove(ctx, commands.RemoveIdentityLink{UserID: userNoPassword, Provider: "google", Actor: userNoPassword, Self: true, FactorVerified: true})
	if !errors.Is(err, commands.ErrLocalFactorMissing) {
		t.Fatalf("no local factor: %v", err)
	}
	if len(e.links.Rows) != 4 || len(e.events.Audits) != 0 {
		t.Fatal("a refusal changes nothing")
	}
	// The admin removal is not a self removal.
	if err := e.links2.Remove(ctx, commands.RemoveIdentityLink{UserID: userNoPassword, Provider: "google", Actor: adminID, CheckUser: true}); err != nil {
		t.Fatalf("admin removal: %v", err)
	}
	// With the proof, the own removal works.
	if err := rm(true, true); err != nil {
		t.Fatalf("with proof: %v", err)
	}
	// A name that is not a provider gives not found and no proof check.
	err = e.links2.Remove(ctx, commands.RemoveIdentityLink{UserID: userA, Provider: "okta", Actor: userA, Self: true})
	if !errors.Is(err, commands.ErrIdentityLinkNotFound) {
		t.Fatalf("wrong provider: %v", err)
	}
	err = e.links2.Remove(ctx, commands.RemoveIdentityLink{UserID: "00000000-0000-4000-8000-0000000000ff", Provider: "okta", Actor: adminID, CheckUser: true})
	if !errors.Is(err, commands.ErrUserNotFound) {
		t.Fatalf("wrong provider and no user: %v", err)
	}
}

// U34 (R3, P23): the check of a local factor. The password and the TOTP code
// work. A wrong value and a used code do not. A user with no password and no
// code gets the error ErrLocalFactorMissing. The failure limit applies.
func TestIssue16_U34_VerifyLocalFactor(t *testing.T) {
	e := newLinkEnv(t)
	secret, _ := e.enable(t, userB, "b@example.com")
	check := func(in commands.LocalFactor) error { return e.cmd.VerifyLocalFactor(ctx, in) }
	if err := check(commands.LocalFactor{UserID: userA, Password: "right password 1"}); err != nil {
		t.Fatalf("password: %v", err)
	}
	if err := check(commands.LocalFactor{UserID: userA, Password: "wrong"}); !errors.Is(err, commands.ErrLocalFactorRequired) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := check(commands.LocalFactor{UserID: userA}); !errors.Is(err, commands.ErrLocalFactorRequired) {
		t.Fatalf("empty: %v", err)
	}
	// A code is not a password, and a password does not open a user with another one.
	if err := check(commands.LocalFactor{UserID: userA, Code: "123456"}); !errors.Is(err, commands.ErrLocalFactorRequired) {
		t.Fatalf("code of a user with no TOTP: %v", err)
	}
	code := e.code(secret, e.now)
	if err := check(commands.LocalFactor{UserID: userB, Code: code}); err != nil {
		t.Fatalf("totp: %v", err)
	}
	if err := check(commands.LocalFactor{UserID: userB, Code: code}); !errors.Is(err, commands.ErrLocalFactorRequired) {
		t.Fatalf("a used code: %v", err)
	}
	if err := check(commands.LocalFactor{UserID: userNoPassword, Password: "x", Code: "123456"}); !errors.Is(err, commands.ErrLocalFactorMissing) {
		t.Fatalf("no factor: %v", err)
	}
	if err := check(commands.LocalFactor{UserID: "00000000-0000-4000-8000-0000000000ff", Password: "x"}); !errors.Is(err, commands.ErrUserNotFound) {
		t.Fatalf("no user: %v", err)
	}
	// The failure limit of the second factor applies.
	var limited bool
	for i := 0; i < 40; i++ {
		if err := check(commands.LocalFactor{UserID: userA, Password: "wrong"}); errors.Is(err, commands.ErrTooManyAttempts) {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("a guess loop must reach the limit")
	}
}

// U35 (R13): the reset of the MFA of a user with a TOTP factor, no passkey, and
// no login method except the factor itself is not blocked by the rule "last
// login method", because the reset removes no login method.
func TestIssue16_U35_ResetWithoutPasskey(t *testing.T) {
	e := newLinkEnv(t)
	e.enable(t, userNoPassword, "nopw@example.com")
	if err := e.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: userNoPassword, Actor: adminID}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	// A user with a passkey that is the only login method is still protected.
	e.addUser(userB, "b2@example.com", domain.UserActive, "")
	e.addPasskey(userB, passkeyID1, "only")
	if err := e.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: userB, Actor: adminID}); !errors.Is(err, commands.ErrLastLoginMethod) {
		t.Fatalf("passkey only: %v", err)
	}
}
