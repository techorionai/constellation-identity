package commands_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/webauthn"
)

// passkeyOnlyEnv makes an env with a user that has a passkey and no password and
// no TOTP. The user is userNoPassword. The user has one session.
func passkeyOnlyEnv(t *testing.T) *idpEnv {
	t.Helper()
	e := newIdpEnv(t)
	e.addPasskey(userNoPassword, passkeyID1, "key")
	e.wa.Asserted = webauthn.Asserted{CredentialID: []byte("cred-" + passkeyID1), SignCount: 5}
	e.addSessionToken("s1", userNoPassword, "session-1")
	e.addSessionToken("s2", userNoPassword, "session-2")
	return e
}

// R3 (P23): a passkey is a local factor for a link. A user with only a passkey
// must pass the passkey check before the start. A check that failed, a ceremony
// of another session, and a second use of a ceremony give no proof.
func TestIssue16_R3_PasskeyConfirmsLink(t *testing.T) {
	e := passkeyOnlyEnv(t)
	link := func(confirm string) commands.StartIdp {
		return commands.StartIdp{Provider: "google", Purpose: domain.FlowLink, SessionToken: "session-1", SecFetchSite: "same-origin", Confirm: confirm}
	}
	confirm := func(token string) (string, error) {
		return e.idp.ConfirmLink(ctx, commands.ConfirmLink{Provider: "google", SessionToken: token, PasskeyBody: []byte(`{}`)})
	}
	// The user has a local factor, so the start with no proof is refused.
	if _, err := e.idp.Start(ctx, link("")); !errors.Is(err, commands.ErrIdpConfirm) {
		t.Fatalf("start with no proof: %v", err)
	}
	// Exploit: a response with no ceremony gives no proof.
	if v, err := confirm("session-1"); !errors.Is(err, commands.ErrPasskeyInvalid) || v != "" {
		t.Fatalf("no ceremony: %q, %v", v, err)
	}
	// Exploit: the ceremony of one session does not serve another session.
	if _, err := e.idp.BeginPasskeyConfirm(ctx, "session-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := confirm("session-1"); !errors.Is(err, commands.ErrPasskeyInvalid) {
		t.Fatalf("ceremony of another session: %v", err)
	}
	// Exploit: a wrong response (the library refuses it) gives no proof.
	if _, err := e.idp.BeginPasskeyConfirm(ctx, "session-1"); err != nil {
		t.Fatal(err)
	}
	e.wa.Err = webauthn.ErrBadOrigin
	if v, err := confirm("session-1"); !errors.Is(err, commands.ErrPasskeyInvalid) || v != "" {
		t.Fatalf("bad response: %q, %v", v, err)
	}
	e.wa.Err = nil
	if len(e.flows.Rows) != 0 {
		t.Fatal("a refused check makes no record")
	}
	// A good response gives the proof. The start then works, with no auth_time rule.
	if _, err := e.idp.BeginPasskeyConfirm(ctx, "session-1"); err != nil {
		t.Fatal(err)
	}
	v, err := confirm("session-1")
	if err != nil || v == "" {
		t.Fatalf("good check: %q, %v", v, err)
	}
	e.start(t, link(v))
	for _, rec := range e.flows.Rows {
		if rec.NeedAuthTime {
			t.Fatal("a user with a passkey needs no auth_time rule")
		}
	}
	// The ceremony works one time.
	if _, err := confirm("session-1"); !errors.Is(err, commands.ErrPasskeyInvalid) {
		t.Fatalf("second use of the ceremony: %v", err)
	}
	// The proof works one time.
	if _, err := e.idp.Start(ctx, link(v)); !errors.Is(err, commands.ErrIdpConfirm) {
		t.Fatalf("second use of the proof: %v", err)
	}
	// The sign count moved, so the same response is a clone.
	if _, err := e.idp.BeginPasskeyConfirm(ctx, "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := confirm("session-1"); !errors.Is(err, commands.ErrPasskeyInvalid) {
		t.Fatalf("replayed sign count: %v", err)
	}
}

// R3: the passkey check needs a fresh session and a user with a passkey.
func TestIssue16_R3_PasskeyBeginChecks(t *testing.T) {
	e := passkeyOnlyEnv(t)
	if _, err := e.idp.BeginPasskeyConfirm(ctx, ""); !errors.Is(err, commands.ErrIdpReauth) {
		t.Fatalf("no session: %v", err)
	}
	e.sessions.Rows["s1"] = func() domain.Session {
		s := e.sessions.Rows["s1"]
		s.AuthTime = e.now.Add(-time.Hour)
		return s
	}()
	if _, err := e.idp.BeginPasskeyConfirm(ctx, "session-1"); !errors.Is(err, commands.ErrIdpReauth) {
		t.Fatalf("old session: %v", err)
	}
	// A user with no passkey has nothing to check.
	e.addSessionToken("s3", userA, "session-3")
	if _, err := e.idp.BeginPasskeyConfirm(ctx, "session-3"); !errors.Is(err, commands.ErrPasskeyInvalid) {
		t.Fatalf("user with no passkey: %v", err)
	}
}

// R3 (P23): a passkey is a local factor for the removal of a link. The page
// checks the passkey, then it removes the link with FactorVerified. A passkey
// only user with no proof is refused.
func TestIssue16_R3_PasskeyConfirmsRemoval(t *testing.T) {
	e := passkeyOnlyEnv(t)
	e.addLink(linkID1, userNoPassword, "google")
	e.addLink(linkID2, userNoPassword, "microsoft")
	rm := func(verified bool) error {
		return e.links2.Remove(ctx, commands.RemoveIdentityLink{
			UserID: userNoPassword, Provider: "google", Actor: userNoPassword, Self: true, FactorVerified: verified,
		})
	}
	if err := rm(false); !errors.Is(err, commands.ErrLocalFactorRequired) {
		t.Fatalf("no proof: %v", err)
	}
	if len(e.links.Rows) != 2 {
		t.Fatal("a refusal changes nothing")
	}
	// A wrong response gives no proof.
	hash := domain.HashSecret("session-1")
	if _, err := e.cmd.BeginPasskeyConfirm(ctx, userNoPassword, hash); err != nil {
		t.Fatal(err)
	}
	e.wa.Err = webauthn.ErrBadOrigin
	err := e.cmd.FinishPasskeyConfirm(ctx, commands.PasskeyConfirm{UserID: userNoPassword, SessionHash: hash, Body: []byte(`{}`)})
	if !errors.Is(err, commands.ErrPasskeyInvalid) {
		t.Fatalf("bad response: %v", err)
	}
	e.wa.Err = nil
	// A good response gives the proof.
	if _, err := e.cmd.BeginPasskeyConfirm(ctx, userNoPassword, hash); err != nil {
		t.Fatal(err)
	}
	if err := e.cmd.FinishPasskeyConfirm(ctx, commands.PasskeyConfirm{UserID: userNoPassword, SessionHash: hash, Body: []byte(`{}`)}); err != nil {
		t.Fatalf("good response: %v", err)
	}
	if err := rm(true); err != nil {
		t.Fatalf("removal with proof: %v", err)
	}
	if len(e.links.Rows) != 1 {
		t.Fatalf("links = %d, want 1", len(e.links.Rows))
	}
	// The ceremony is for one user. The state of another user is not a proof.
	if _, err := e.cmd.BeginPasskeyConfirm(ctx, userNoPassword, hash); err != nil {
		t.Fatal(err)
	}
	err = e.cmd.FinishPasskeyConfirm(ctx, commands.PasskeyConfirm{UserID: userA, SessionHash: hash, Body: []byte(`{}`)})
	if !errors.Is(err, commands.ErrPasskeyInvalid) {
		t.Fatalf("ceremony of another user: %v", err)
	}
}

// R3 (P23): the removal of a user with no local factor needs an upstream login
// with a valid auth_time. A user with a local factor does not pass with the
// upstream proof alone.
func TestIssue16_R3_RemovalWithUpstreamAuthTime(t *testing.T) {
	e := newLinkEnv(t)
	e.addLink(linkID1, userNoPassword, "google")
	e.addLink(linkID2, userNoPassword, "microsoft")
	e.addLink("00000000-0000-4000-8000-0000000000d5", userA, "google")
	e.addLink("00000000-0000-4000-8000-0000000000d6", userA, "microsoft")
	rm := func(user string, fresh, verified bool) error {
		return e.links2.Remove(ctx, commands.RemoveIdentityLink{
			UserID: user, Provider: "google", Actor: user, Self: true, UpstreamFresh: fresh, FactorVerified: verified,
		})
	}
	// No local factor and no valid auth_time: refused.
	if err := rm(userNoPassword, false, false); !errors.Is(err, commands.ErrLocalFactorMissing) {
		t.Fatalf("no auth_time: %v", err)
	}
	if len(e.links.Rows) != 4 || len(e.events.Audits) != 0 {
		t.Fatal("a refusal changes nothing")
	}
	// A user with a password: the upstream proof does not replace the password.
	if err := rm(userA, true, false); !errors.Is(err, commands.ErrLocalFactorRequired) {
		t.Fatalf("local factor with upstream proof only: %v", err)
	}
	if len(e.links.Rows) != 4 {
		t.Fatal("a refusal changes nothing")
	}
	// P24: the stored mark of the access token replaces the amr value. A jti
	// with no mark, a mark of another user, and a mark that ended do not pass.
	rmJTI := func(user, jti string) error {
		return e.links2.Remove(ctx, commands.RemoveIdentityLink{
			UserID: user, Provider: "google", Actor: user, Self: true, AccessTokenID: jti,
		})
	}
	if err := e.sessions.MarkAccessToken(ctx, "jti-other", userA, e.now.Add(5*time.Minute), e.now); err != nil {
		t.Fatal(err)
	}
	if err := e.sessions.MarkAccessToken(ctx, "jti-ended", userNoPassword, e.now.Add(-time.Second), e.now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	for name, jti := range map[string]string{"no mark": "jti-none", "empty": "", "mark of another user": "jti-other", "mark ended": "jti-ended"} {
		if err := rmJTI(userNoPassword, jti); !errors.Is(err, commands.ErrLocalFactorMissing) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if len(e.links.Rows) != 4 {
		t.Fatal("a refusal changes nothing")
	}
	// A user with a local factor does not pass with a mark.
	if err := e.sessions.MarkAccessToken(ctx, "jti-a", userA, e.now.Add(5*time.Minute), e.now); err != nil {
		t.Fatal(err)
	}
	if err := rmJTI(userA, "jti-a"); !errors.Is(err, commands.ErrLocalFactorRequired) {
		t.Fatalf("local factor with a mark only: %v", err)
	}
	// No local factor and a valid mark: the removal works.
	if err := e.sessions.MarkAccessToken(ctx, "jti-good", userNoPassword, e.now.Add(5*time.Minute), e.now); err != nil {
		t.Fatal(err)
	}
	if err := rmJTI(userNoPassword, "jti-good"); err != nil {
		t.Fatalf("with the mark: %v", err)
	}
	if len(e.links.Rows) != 3 || len(e.events.Audits) != 1 {
		t.Fatalf("links = %d, audits = %d", len(e.links.Rows), len(e.events.Audits))
	}
	e.addLink(linkID1, userNoPassword, "google")
	e.events.Audits = nil
	// No local factor and a valid auth_time: the removal works.
	if err := rm(userNoPassword, true, false); err != nil {
		t.Fatalf("with auth_time: %v", err)
	}
	if len(e.links.Rows) != 3 || len(e.events.Audits) != 1 {
		t.Fatalf("links = %d, audits = %d", len(e.links.Rows), len(e.events.Audits))
	}
}

// unlinkStart is the start of the purpose unlink for a provider.
func unlinkStart(login, remove, token string) commands.StartIdp {
	return commands.StartIdp{
		Provider: login, Purpose: domain.FlowUnlink, SessionToken: token, SecFetchSite: "same-origin", RemoveProvider: remove,
	}
}

// R3 (P23): the flow unlink. A user with no local factor logs in at an upstream
// provider with a valid auth_time, with an account of the user. The removal then
// runs. Each exploit leaves the links as they are.
func TestIssue16_R3_UnlinkFlow(t *testing.T) {
	e := newIdpEnv(t)
	e.addSessionToken("s1", userNoPassword, "session-1")
	e.sessions.Rows["s1"] = func() domain.Session {
		s := e.sessions.Rows["s1"]
		s.AuthMethods = domain.MethodsFederated()
		return s
	}()
	const (
		linkG = "00000000-0000-4000-8000-0000000000d3"
		linkM = "00000000-0000-4000-8000-0000000000d4"
	)
	reset := func() {
		e.links.Rows = map[string]domain.IdentityLink{}
		e.addLink(linkG, userNoPassword, "google")
		e.addLink(linkM, userNoPassword, "microsoft")
		e.addLink("00000000-0000-4000-8000-0000000000d9", userB, "google")
		e.events.Audits = nil
	}
	reset()
	fresh := e.now.Add(-time.Minute)
	run := func(id domain.UpstreamIdentity, in commands.StartIdp) (commands.IdpResult, error) {
		state, binding := e.start(t, in)
		e.client.Identity = id
		return e.callback(state, binding, commands.CallbackIdp{Provider: in.Provider, SessionToken: "session-1"})
	}

	// A user with a local factor does not use this flow.
	e.addSessionToken("sa", userA, "session-a")
	if _, err := e.idp.Start(ctx, unlinkStart("google", "microsoft", "session-a")); !errors.Is(err, commands.ErrIdpFailed) {
		t.Fatalf("user with a local factor: %v", err)
	}
	// A wrong removal provider, a missing session, and a cross-site start.
	for name, in := range map[string]commands.StartIdp{
		"provider not valid": unlinkStart("google", "okta", "session-1"),
		"no remove provider": unlinkStart("google", "", "session-1"),
	} {
		if _, err := e.idp.Start(ctx, in); !errors.Is(err, commands.ErrIdpFailed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := e.idp.Start(ctx, unlinkStart("google", "microsoft", "")); !errors.Is(err, commands.ErrIdpReauth) {
		t.Fatalf("no session: %v", err)
	}
	cross := unlinkStart("google", "microsoft", "session-1")
	cross.SecFetchSite = "cross-site"
	if _, err := e.idp.Start(ctx, cross); !errors.Is(err, commands.ErrIdpFailed) {
		t.Fatalf("cross-site start: %v", err)
	}
	if len(e.flows.Rows) != 0 {
		t.Fatal("a refused start makes no record")
	}

	mine := domain.UpstreamIdentity{Subject: "subject-" + linkG, AuthTime: fresh, IssuedAt: e.now}
	t.Run("no auth_time", func(t *testing.T) {
		// The exploit: Google sends no auth_time. The removal is refused.
		reset()
		id := mine
		id.AuthTime = time.Time{}
		if _, err := run(id, unlinkStart("google", "microsoft", "session-1")); !errors.Is(err, commands.ErrIdpFailed) {
			t.Fatalf("err = %v", err)
		}
		if len(e.links.Rows) != 3 || len(e.events.Audits) != 0 {
			t.Fatal("a refusal changes nothing")
		}
	})
	t.Run("old auth_time", func(t *testing.T) {
		reset()
		id := mine
		id.AuthTime = e.now.Add(-10 * time.Minute)
		if _, err := run(id, unlinkStart("google", "microsoft", "session-1")); !errors.Is(err, commands.ErrIdpFailed) {
			t.Fatalf("err = %v", err)
		}
		if len(e.links.Rows) != 3 {
			t.Fatal("a refusal changes nothing")
		}
	})
	t.Run("account of the attacker", func(t *testing.T) {
		// The exploit: the holder of a young session logs in with an own account
		// that has a fresh auth_time. The account is not linked to the user.
		reset()
		id := domain.UpstreamIdentity{Subject: "attacker-account", AuthTime: fresh, IssuedAt: e.now}
		if _, err := run(id, unlinkStart("google", "microsoft", "session-1")); !errors.Is(err, commands.ErrIdpFailed) {
			t.Fatalf("err = %v", err)
		}
		if len(e.links.Rows) != 3 {
			t.Fatal("a refusal changes nothing")
		}
	})
	t.Run("account of another user", func(t *testing.T) {
		reset()
		id := domain.UpstreamIdentity{Subject: "subject-00000000-0000-4000-8000-0000000000d9", AuthTime: fresh, IssuedAt: e.now}
		if _, err := run(id, unlinkStart("google", "microsoft", "session-1")); !errors.Is(err, commands.ErrIdpFailed) {
			t.Fatalf("err = %v", err)
		}
		if len(e.links.Rows) != 3 {
			t.Fatal("a refusal changes nothing")
		}
	})
	t.Run("another session", func(t *testing.T) {
		reset()
		state, binding := e.start(t, unlinkStart("google", "microsoft", "session-1"))
		e.addSessionToken("s2", userNoPassword, "session-2")
		e.client.Identity = mine
		if _, err := e.callback(state, binding, commands.CallbackIdp{SessionToken: "session-2"}); !errors.Is(err, commands.ErrIdpExpired) {
			t.Fatalf("err = %v", err)
		}
		if len(e.links.Rows) != 3 {
			t.Fatal("a refusal changes nothing")
		}
	})
	t.Run("good", func(t *testing.T) {
		reset()
		res, err := run(mine, unlinkStart("google", "microsoft", "session-1"))
		if err != nil {
			t.Fatal(err)
		}
		if res.Kind != commands.IdpUnlinked || !res.SessionEnded {
			t.Fatalf("result = %+v", res)
		}
		if _, ok := e.links.Rows[linkM]; ok || len(e.links.Rows) != 2 {
			t.Fatal("the microsoft link must be gone")
		}
		if len(e.events.Audits) != 1 || !e.revoked("s1") {
			t.Fatal("the removal writes an audit entry and ends the session with fed")
		}
	})
	t.Run("last login method", func(t *testing.T) {
		reset()
		delete(e.links.Rows, linkM)
		e.sessions.Rows["s1"] = func() domain.Session { s := e.sessions.Rows["s1"]; s.RevokedAt = nil; return s }()
		if _, err := run(mine, unlinkStart("google", "google", "session-1")); !errors.Is(err, commands.ErrLastLoginMethod) {
			t.Fatalf("err = %v", err)
		}
		if _, ok := e.links.Rows[linkG]; !ok {
			t.Fatal("the last link must stay")
		}
	})
}

// R3 (P23, P24): a login with an upstream ID token that has a valid auth_time
// sets the flag of the session in the storage of the service. A login with no
// auth_time, or with an old auth_time, does not. In all cases, amr has only
// "fed". The flag serves the removal through the API.
func TestIssue16_R3_LoginMarker(t *testing.T) {
	e := newIdpEnv(t)
	e.addLink(linkID1, userNoPassword, "google")
	for name, c := range map[string]struct {
		authTime time.Time
		marker   bool
	}{
		"fresh auth_time": {e.now.Add(-time.Minute), true},
		"no auth_time":    {time.Time{}, false},
		"old auth_time":   {e.now.Add(-time.Hour), false},
		"future":          {e.now.Add(time.Hour), false},
	} {
		e.client.Identity = domain.UpstreamIdentity{Subject: "subject-" + linkID1, AuthTime: c.authTime, IssuedAt: e.now}
		state, binding := e.start(t, loginStart())
		res, err := e.callback(state, binding, commands.CallbackIdp{IP: "1.1.1.1"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		methods := res.Session.AuthMethods
		if !slices.Equal(methods, []string{domain.AMRFederated}) {
			t.Fatalf("%s: methods = %v", name, methods)
		}
		if got := e.sessions.Rows[res.Session.SessionID].UpstreamAuthValid; got != c.marker {
			t.Fatalf("%s: stored flag = %v", name, got)
		}
	}
}
