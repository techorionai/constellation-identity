package commands_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// oneTokenEntry returns the only audit entry of a recorder and checks the action.
func oneTokenEntry(t *testing.T, ev *mock.Events, result string) mock.AuditRow {
	t.Helper()
	if len(ev.Audits) != 1 || ev.Audits[0].Action != commands.ActionTokenIssue || ev.Audits[0].Result != result {
		t.Fatalf("audits = %+v", ev.Audits)
	}
	return ev.Audits[0]
}

// Issue26_U3: each token path writes one entry with the grant, the client, the
// audience, the scopes, the jti, and the expiry time. The entry has no token.
func TestIssue26_U3_TokenEntries(t *testing.T) {
	t.Run("client credentials", func(t *testing.T) {
		f := newFixture(t)
		res, err := f.cmd.Execute(ctx, request(f.assertion(t, nil)))
		if err != nil {
			t.Fatal(err)
		}
		a := oneTokenEntry(t, f.ev, "success")
		if a.Actor != "helpdesk" || a.TargetType != "client" || a.TargetUserID != "helpdesk" {
			t.Fatalf("entry = %+v", a)
		}
		if a.Details["grant"] != "client_credentials" || a.Details["clientId"] != "helpdesk" || a.Details["audience"] != "demo" ||
			a.Details["jti"] != "token-1" || a.Details["expiresAt"] == "" || fmt.Sprint(a.Details["scopes"]) != "[demo:ticket:read]" {
			t.Fatalf("details = %v", a.Details)
		}
		if strings.Contains(fmt.Sprint(a.Details), res.AccessToken) {
			t.Fatal("the entry has the token")
		}
	})
	t.Run("token exchange with an agent", func(t *testing.T) {
		e := newExchangeEnv(t)
		in := e.withAgent(e.in(t), agent1)
		if _, err := e.cmd.Execute(ctx, in); err != nil {
			t.Fatal(err)
		}
		a := oneTokenEntry(t, e.fixture.ev, "success")
		if a.Actor != agent1 || a.TargetType != "user" || a.TargetUserID != user1 || a.Details["grant"] != "token_exchange" ||
			a.Details["subjectType"] != "user" || a.Details["clientId"] != "helpdesk" {
			t.Fatalf("entry = %+v", a)
		}
		if _, ok := a.Details["act"]; ok {
			t.Fatal("the entry has act")
		}
	})
	t.Run("token exchange with no agent", func(t *testing.T) {
		e := newExchangeEnv(t)
		if _, err := e.cmd.Execute(ctx, e.in(t)); err != nil {
			t.Fatal(err)
		}
		if a := oneTokenEntry(t, e.fixture.ev, "success"); a.Actor != "helpdesk" {
			t.Fatalf("entry = %+v", a)
		}
	})
}

// Issue26_U4: a writer error gives no token and the OAuth error
// temporarily_unavailable.
func TestIssue26_U4_WriterErrorGivesNoToken(t *testing.T) {
	f := newFixture(t)
	f.ev.AuditErr = errAuditDown
	res, err := f.cmd.Execute(ctx, request(f.assertion(t, nil)))
	if oauthCode(t, err) != apperrors.OAuthTemporarilyUnavailable || res.AccessToken != "" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	e := newExchangeEnv(t)
	e.fixture.ev.AuditErr = errAuditDown
	xr, err := e.cmd.Execute(ctx, e.in(t))
	if oauthCode(t, err) != apperrors.OAuthTemporarilyUnavailable || xr.AccessToken != "" {
		t.Fatalf("exchange: res = %+v, err = %v", xr, err)
	}
}

// Issue26_U5: a wrong password writes a denied entry. The entry has the user as
// target for a known email and no target for an unknown email. It has no email.
func TestIssue26_U5_LoginDenied(t *testing.T) {
	e := newEnv()
	e.addUser("active", "active@example.com", domain.UserActive, "right password 1")
	cmd := e.login()
	_, _ = cmd.Execute(ctx, commands.Login{Email: "active@example.com", Password: "wrong", IP: "1.1.1.1"})
	_, _ = cmd.Execute(ctx, commands.Login{Email: "nobody@example.com", Password: "wrong", IP: "1.1.1.1"})
	if len(e.logins.Audits) != 2 {
		t.Fatalf("audits = %+v", e.logins.Audits)
	}
	known, unknown := e.logins.Audits[0], e.logins.Audits[1]
	if known.Action != commands.ActionSessionLogin || known.Result != "denied" || known.Actor != "" || known.TargetUserID != "active" ||
		known.Details["method"] != "password" {
		t.Fatalf("known = %+v", known)
	}
	if unknown.Result != "denied" || unknown.TargetUserID != "" || unknown.TargetType != "" {
		t.Fatalf("unknown = %+v", unknown)
	}
	for _, a := range e.logins.Audits {
		if strings.Contains(fmt.Sprint(a.Details), "example.com") {
			t.Fatalf("the entry has the email: %+v", a)
		}
	}
	// A good login writes a success entry with the user as actor.
	if _, err := cmd.Execute(ctx, commands.Login{Email: "active@example.com", Password: "right password 1", IP: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if got := e.logins.Audits[2]; got.Result != "success" || got.Actor != "active" || got.TargetUserID != "active" || got.Details["method"] != "password" {
		t.Fatalf("success = %+v", got)
	}
}

// A login with a writer error makes no session.
func TestIssue26_LoginWriterError(t *testing.T) {
	e := newEnv()
	e.addUser("active", "active@example.com", domain.UserActive, "right password 1")
	e.logins.AuditErr = errAuditDown
	_, err := e.login().Execute(ctx, commands.Login{Email: "active@example.com", Password: "right password 1", IP: "1.1.1.1"})
	if !errors.Is(err, errAuditDown) {
		t.Fatalf("err = %v, want the error of the writer", err)
	}
}

// Issue26_U6: unlock-login with a Valkey error writes no entry. With no error it
// writes one entry. The entry has the user as target and no email.
func TestIssue26_U6_UnlockLogin(t *testing.T) {
	e := newEnv()
	e.addUser("u", "u@example.com", domain.UserActive, "pw")
	ev := &mock.Events{}
	l := mock.NewLimiter()
	l.Emails["u@example.com"] = 6
	cmd := commands.NewUnlockLogin(l, nil).WithAudit(e.users, mock.Tx{}, ev)
	if got, err := cmd.Execute(ctx, commands.UnlockLogin{Email: " U@Example.com "}); err != nil || !got {
		t.Fatalf("got %v, err %v", got, err)
	}
	if len(ev.Audits) != 1 {
		t.Fatalf("audits = %+v", ev.Audits)
	}
	a := ev.Audits[0]
	if a.Action != commands.ActionLoginUnlock || a.TargetType != "user" || a.TargetUserID != "u" ||
		a.Details["origin"] != "cli" || a.Details["knownUser"] != true || strings.Contains(fmt.Sprint(a.Details), "example.com") {
		t.Fatalf("audits = %+v", ev.Audits)
	}
	if _, err := cmd.Execute(ctx, commands.UnlockLogin{Email: "nobody@example.com"}); err != nil {
		t.Fatal(err)
	}
	if b := ev.Audits[1]; b.TargetUserID != "" || b.Details["knownUser"] != false {
		t.Fatalf("unknown = %+v", b)
	}
	ev.Audits = nil
	l.Err = errors.New("valkey down")
	if _, err := cmd.Execute(ctx, commands.UnlockLogin{Email: "u@example.com"}); err == nil || len(ev.Audits) != 0 {
		t.Fatalf("err = %v, audits = %+v, want an error and no entry", err, ev.Audits)
	}
	// A command with no audit writer does nothing.
	if _, err := commands.NewUnlockLogin(l, nil).Execute(ctx, commands.UnlockLogin{Email: "u@example.com"}); !errors.Is(err, commands.ErrNoAuditWriter) {
		t.Fatalf("err = %v, want ErrNoAuditWriter", err)
	}
}

// Issue26_U9: a request with invalid_client writes a denied entry with the actor
// identity and no client ID for an unknown client. A writer error does not change
// the OAuth error, and the log has no secret.
func TestIssue26_U9_DeniedEntry(t *testing.T) {
	f := newFixture(t)
	unknown := func(c map[string]any) { c["sub"] = "nobody"; c["iss"] = "nobody" }
	_, err := f.cmd.Execute(ctx, request(f.assertion(t, unknown)))
	if oauthCode(t, err) != apperrors.OAuthInvalidClient {
		t.Fatalf("err = %v", err)
	}
	a := oneTokenEntry(t, f.ev, "denied")
	if a.Actor != "" || a.Details["reason"] != "invalid_client" || a.Details["grant"] != "client_credentials" {
		t.Fatalf("entry = %+v", a)
	}
	if _, ok := a.Details["clientId"]; ok {
		t.Fatalf("an unknown client ID is in the entry: %+v", a.Details)
	}
	// A request that fails the validation writes no entry.
	f.ev.Audits = nil
	in := request(f.assertion(t, nil))
	in.GrantType = "password"
	if _, err := f.cmd.Execute(ctx, in); oauthCode(t, err) != apperrors.OAuthUnsupportedGrantType || len(f.ev.Audits) != 0 {
		t.Fatalf("err = %v, audits = %+v", err, f.ev.Audits)
	}
	// A writer error keeps the OAuth error.
	f.ev.AuditErr = errAuditDown
	f.log.Reset()
	_, err = f.cmd.Execute(ctx, request(f.assertion(t, unknown)))
	if oauthCode(t, err) != apperrors.OAuthInvalidClient {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(f.log.String(), "identity.audit.failed") {
		t.Fatalf("log = %s", f.log.String())
	}
}

// A known client with a refused scope gets a denied entry with the client as
// actor and target.
func TestIssue26_DeniedKnownClient(t *testing.T) {
	f := newFixture(t)
	in := request(f.assertion(t, nil))
	in.Scope = "demo:ticket:delete"
	_, err := f.cmd.Execute(ctx, in)
	if oauthCode(t, err) != apperrors.OAuthInvalidScope {
		t.Fatalf("err = %v", err)
	}
	a := oneTokenEntry(t, f.ev, "denied")
	if a.Actor != "helpdesk" || a.TargetUserID != "helpdesk" || a.Details["clientId"] != "helpdesk" || a.Details["reason"] != "invalid_scope" {
		t.Fatalf("entry = %+v", a)
	}
}
